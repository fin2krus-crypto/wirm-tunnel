#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef WINRM_PORT
#define WINRM_PORT 5986
#endif

SEC("tc")
int synack_win_order(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP || ip->ihl < 5)
        return TC_ACT_OK;

    __u32 l3_len = (__u32)ip->ihl * 4;
    if (l3_len < 20 || l3_len > 60)
        return TC_ACT_OK;

    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + l3_len);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    if (tcp->source != bpf_htons(WINRM_PORT))
        return TC_ACT_OK;

    if (!tcp->syn || !tcp->ack || tcp->rst || tcp->fin)
        return TC_ACT_OK;

    if (tcp->doff != 8)
        return TC_ACT_OK;

    __u32 l4_off = sizeof(struct ethhdr) + l3_len;
    __u8 old_opts[12];
    if (bpf_skb_load_bytes(skb, l4_off + 20, old_opts, 12) < 0)
        return TC_ACT_OK;

    if (old_opts[0] != 2 || old_opts[1] != 4)
        return TC_ACT_OK;

    __u8 ws_val = 0;
    __u8 has_ws = 0;
    __u8 has_sack = 0;

    #pragma unroll
    for (int i = 0; i < 12; ) {
        __u8 kind = old_opts[i];
        if (kind == 0) {
            break;
        } else if (kind == 1) {
            i += 1;
            continue;
        } else if (kind == 8) {
            return TC_ACT_OK;
        } else if (kind == 2 && i + 4 <= 12 && old_opts[i + 1] == 4) {
            i += 4;
            continue;
        } else if (kind == 3 && i + 3 <= 12 && old_opts[i + 1] == 3) {
            ws_val = old_opts[i + 2];
            has_ws = 1;
            i += 3;
            continue;
        } else if (kind == 4 && i + 2 <= 12 && old_opts[i + 1] == 2) {
            has_sack = 1;
            i += 2;
            continue;
        } else {
            return TC_ACT_OK;
        }
    }

    if (!has_ws || !has_sack)
        return TC_ACT_OK;

    __u8 new_opts[12];
    new_opts[0] = 2;
    new_opts[1] = 4;
    new_opts[2] = old_opts[2];
    new_opts[3] = old_opts[3];
    new_opts[4] = 1;
    new_opts[5] = 3;
    new_opts[6] = 3;
    new_opts[7] = ws_val;
    new_opts[8] = 1;
    new_opts[9] = 1;
    new_opts[10] = 4;
    new_opts[11] = 2;

    __s64 diff = bpf_csum_diff((__be32 *)old_opts, 12, (__be32 *)new_opts, 12, 0);
    if (bpf_skb_store_bytes(skb, l4_off + 20, new_opts, 12, 0) < 0)
        return TC_ACT_OK;

    bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct tcphdr, check), 0, diff, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
