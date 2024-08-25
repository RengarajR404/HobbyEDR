#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ipv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/inetdevice.h>
#include <linux/inet_diag.h>
#include <linux/net.h>

#define MAX_IPS 1024

extern int xdp_prog(struct xdp_md *ctx);

static struct bpf_prog *prog;
static struct bpf_map *blocked_ips_map;
static struct in6_addr blocked_ips[MAX_IPS];
static int num_blocked_ips = 0;

static int load_blocked_ips(const char *filename) {
    struct file *file;
    mm_segment_t old_fs;
    char buf[128];
    struct in6_addr ip_addr;
    ssize_t len;
    loff_t pos = 0;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Error opening file: %ld\n", PTR_ERR(file));
        set_fs(old_fs);
        return -EIO;
    }

    while ((len = kernel_read(file, buf, sizeof(buf), &pos)) > 0) {
        buf[len] = '\0';

        if (in6_pton(buf, len, ip_addr.s6_addr, -1, NULL) == 1) {
            bpf_map_update_elem(blocked_ips_map, &ip_addr, &num_blocked_ips, BPF_ANY);
            pr_info("Blocked IP: %pI6\n", &ip_addr);
            num_blocked_ips++;
        } else {
            pr_err("Invalid IP address in file: %s\n", buf);
        }
    }

    filp_close(file, NULL);
    set_fs(old_fs);
    return 0;
}

static int __init xdp_ip_blocker_init(void) {
    struct bpf_prog_load_attr prog_load_attr = {
        .file = "./xdp_prog.o",
        .prog_type = BPF_PROG_TYPE_XDP,
    };

    struct bpf_object *obj;
    struct bpf_program *prog;
    int ret;

    ret = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog);
    if (ret) {
        pr_err("Failed to load BPF program: %d\n", ret);
        return ret;
    }

    prog = bpf_object__find_program_by_title(obj, "xdp_filter");
    if (!prog) {
        pr_err("Failed to find program section 'xdp_filter'\n");
        return -ENOENT;
    }

    prog = bpf_program__fd(prog);
    blocked_ips_map = bpf_object__find_map_by_name(obj, "blocked_ips");
    if (!blocked_ips_map) {
        pr_err("Failed to find 'blocked_ips' map\n");
        return -ENOENT;
    }

    ret = load_blocked_ips("/etc/HobbyEDR/bad_ips.lst");
    if (ret) {
        pr_err("Failed to load blocked IPs: %d\n", ret);
        return ret;
    }

    return 0;
}

static void __exit xdp_ip_blocker_exit(void) {
    pr_info("Unloading XDP IP Blocker module\n");
}

module_init(xdp_ip_blocker_init);
module_exit(xdp_ip_blocker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rengaraj R");
MODULE_DESCRIPTION("XDP IP Blocker using eBPF");

