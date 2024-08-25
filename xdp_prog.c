#include <linux/bpf.h>
#include <linux/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>

// BPF map to hold blocked IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct in6_addr);
    __type(value, __u32);
} blocked_ips SEC(".maps");

// XDP program to drop packets from blocked IPs
SEC("xdp_filter")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct ipv6hdr *ip6;
    struct in6_addr ip_addr;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto == htons(ETH_P_IP)) {
        ip = data + sizeof(*eth);
        if (ip + 1 > data_end)
            return XDP_PASS;

        // Convert IPv4 address to IPv6-mapped IPv4 address
        ip_addr.s6_addr32[0] = 0;
        ip_addr.s6_addr32[1] = 0;
        ip_addr.s6_addr32[2] = htonl(0xffff);
        ip_addr.s6_addr32[3] = ip->saddr;

        if (bpf_map_lookup_elem(&blocked_ips, &ip_addr))
            return XDP_DROP;

    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
        ip6 = data + sizeof(*eth);
        if (ip6 + 1 > data_end)
            return XDP_PASS;

        if (bpf_map_lookup_elem(&blocked_ips, &ip6->saddr))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

