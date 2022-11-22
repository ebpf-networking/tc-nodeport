// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Set this flag to enable/ disable debug messages */
#define DEBUG_ENABLED false

#define DEBUG_BPF_PRINTK(...) if(DEBUG_ENABLED) {bpf_printk(__VA_ARGS__);}


#define TC_ACT_OK	0
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define TEST_NODEPORT   ((unsigned short) 31000)

struct np_backends {
        __be32 be1;
        __be32 be2;
        __u16 targetPort;
};

/* Simplified map definition for initial POC */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, __u16);
        __type(value, struct np_backends);
} svc_map SEC(".maps");

struct bpf_ct_opts {
        s32 netns_id;
        s32 error;
        u8 l4proto;
        u8 dir;
        u8 reserved[2];
};

struct nf_conn *
bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, u32,
                  struct bpf_ct_opts *, u32) __ksym;

struct nf_conn *
bpf_skb_ct_alloc(struct __sk_buff *skb_ctx, struct bpf_sock_tuple *bpf_tuple,
                 u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;

struct nf_conn *bpf_ct_insert_entry(struct nf_conn *nfct_i) __ksym;

int bpf_ct_set_nat_info(struct nf_conn *nfct,
                        union nf_inet_addr *addr, int port,
                        enum nf_nat_manip_type manip) __ksym;

void bpf_ct_set_timeout(struct nf_conn *nfct, u32 timeout) __ksym;

int bpf_ct_set_status(const struct nf_conn *nfct, u32 status) __ksym;

void bpf_ct_release(struct nf_conn *) __ksym;

// static __always_inline int nodeport_lb4(struct __sk_buff *ctx) {

/* Not marking this function to be inline for now */
int nodeport_lb4(struct __sk_buff *ctx) {

        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;
        u64 nh_off = sizeof(*eth);
        struct np_backends *lkup;
        __be32  b1;
        __be32  b2;

        if (data + nh_off > data_end)
            return TC_ACT_OK;

        switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_IP: {
                struct bpf_sock_tuple bpf_tuple = {};
                struct iphdr *iph = data + nh_off;
                struct bpf_ct_opts opts_def = {
                        .netns_id = -1,
                };
                struct nf_conn *ct;
                // bool ret;

	        if ((void *)(iph + 1) > data_end)
                    return TC_ACT_OK;

                opts_def.l4proto = iph->protocol;
                bpf_tuple.ipv4.saddr = iph->saddr;
                bpf_tuple.ipv4.daddr = iph->daddr;

                if (iph->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                        if ((void *)(tcph + 1) > data_end)
                            return TC_ACT_OK;

                        bpf_tuple.ipv4.sport = tcph->source;
                        bpf_tuple.ipv4.dport = tcph->dest;
                } else if (iph->protocol == IPPROTO_UDP) {
                        struct udphdr *udph = (struct udphdr *)(iph + 1);

                        if ((void *)(udph + 1) > data_end)
                            return TC_ACT_OK;

                        bpf_tuple.ipv4.sport = udph->source;
                        bpf_tuple.ipv4.dport = udph->dest;
                } else {
                        return TC_ACT_OK;
                }

                // Skip all BPF-CT unless port is of the target nodeport 
/**
                if (bpf_tuple.ipv4.dport != bpf_ntohs(TEST_NODEPORT)) {
                        return TC_ACT_OK;
                }
**/

                u16 key = bpf_ntohs(bpf_tuple.ipv4.dport);

                lkup = (struct np_backends *) bpf_map_lookup_elem(&svc_map, &key);

                if (lkup) {
                    b1 = lkup->be1;
                    b2 = lkup->be2;
                    DEBUG_BPF_PRINTK("lkup result: Full BE1 0x%X  BE2 0x%X \n",
                                      b1, b2)
                } else {
                    DEBUG_BPF_PRINTK("lkup result: NULL \n")
                    return TC_ACT_OK;
                }


                ct = bpf_skb_ct_lookup(ctx, &bpf_tuple,
                                       sizeof(bpf_tuple.ipv4),
                                       &opts_def, sizeof(opts_def));
                // ret = !!ct;
                if (ct) {
                    DEBUG_BPF_PRINTK("CT lookup (ct found) 0x%X\n", ct)
                    DEBUG_BPF_PRINTK("Timeout %u  status 0x%X dport 0x%X \n",  
                                ct->timeout, ct->status, bpf_tuple.ipv4.dport)
                    if (iph->protocol == IPPROTO_TCP) {
                        DEBUG_BPF_PRINTK("TCP proto state %u flags  %u/ %u  last_dir  %u  \n",
                                ct->proto.tcp.state,
                                ct->proto.tcp.seen[0].flags, ct->proto.tcp.seen[1].flags,
                                ct->proto.tcp.last_dir)
                    }
                    bpf_ct_release(ct);
                } else {
                    DEBUG_BPF_PRINTK("CT lookup (no entry) 0x%X\n", 0)
                    DEBUG_BPF_PRINTK("dport 0x%X 0x%X\n",  
                                bpf_tuple.ipv4.dport, bpf_htons(TEST_NODEPORT))
                    DEBUG_BPF_PRINTK("Got IP packet: dest: %pI4, protocol: %u", 
                                &(iph->daddr), iph->protocol)
                    /* Create a new CT entry */

                    struct nf_conn *nct = bpf_skb_ct_alloc(ctx,
                                &bpf_tuple, sizeof(bpf_tuple.ipv4),
                                &opts_def, sizeof(opts_def));

                    if (!nct) {
                        DEBUG_BPF_PRINTK("bpf_skb_ct_alloc() failed\n")
                        return TC_ACT_OK;
                    }

                    // Rudimentary load balancing for now based on received source port

                    union nf_inet_addr addr = {};
 
                    addr.ip = b1;

                    if (bpf_htons(bpf_tuple.ipv4.sport) % 2) {
                        addr.ip = b2;
                    }

                    /* Add DNAT info */
                    bpf_ct_set_nat_info(nct, &addr, lkup->targetPort, NF_NAT_MANIP_DST);

                    /* Now add SNAT (masquerade) info */
                    /* For now using the node IP, check this TODO */
                    /* addr.ip = 0x0101F00a;     Kind-Net bridge IP 10.240.1.1 */

                    addr.ip = bpf_tuple.ipv4.daddr;

                    bpf_ct_set_nat_info(nct, &addr, -1, NF_NAT_MANIP_SRC);

                    bpf_ct_set_timeout(nct, 30000);
                    bpf_ct_set_status(nct, IP_CT_NEW);

                    ct = bpf_ct_insert_entry(nct);

                    DEBUG_BPF_PRINTK("bpf_ct_insert_entry() returned ct 0x%x\n", ct)

                    if (ct) {
                        bpf_ct_release(ct);
                    }
                }
        }
        default:
                break;
        }
out:

    return TC_ACT_OK;

}


SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
        int ret = TC_ACT_OK;
#if 0
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2h = NULL;
	struct iphdr *ip4h = NULL;
        struct tcphdr *tcph = NULL;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2h = data;
	if ((void *)(l2h + 1) > data_end)
		return TC_ACT_OK;

	ip4h = (struct iphdr *)(l2h + 1);
	if ((void *)(ip4h + 1) > data_end)
		return TC_ACT_OK;

        if (ip4h->protocol == IPPROTO_TCP) {
                tcph = (struct tcphdr *)(ip4h + 1);

                if ((void *)(tcph + 1) > data_end) {
		        return TC_ACT_OK;
                }

                if (tcph->dest == bpf_htons(TEST_NODEPORT)) {
                    DEBUG_BPF_PRINTK("1) Got IP Nodeport packet: dest: %pI4, protocol: %u", &(ip4h->daddr), ip4h->protocol);
                }
        }
#endif

        ret = nodeport_lb4(ctx);
	return ret;
}

char __license[] SEC("license") = "GPL";
