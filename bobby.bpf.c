#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>	/* Helpers to convert endian (e.g., bpf_ntohs()) */
#include <linux/if_ether.h>	/* Definition of struct ethhdr */
#include "if_arp.h"	/* Definition of struct arphdr */
#include "common.h"		/* Definition of struct event*/
#include <string.h>

/* Based on https://github.com/saultab/arp-monitor-ebpf-xdp */

/* BPF ring buffer map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	/* Retrieve pointers to the begin and end of the packet buffer */
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Interpret the first part of the packet as an ethernet header */
	struct ethhdr *eth = data;

	/* Every time we access the packet buffer the eBPF verifier requires us
	 * to explicitly check that the address we are accessing doesn't exceed
	 * the buffer limits
	 */
	if (data + sizeof(*eth) > data_end)
	{
		/* The packet is malformed, the XDP_DROP return code
		 * instructs the kernel to drop it
		 */
		return XDP_DROP;
	}

	/* Check if packet is ARP */
	if (eth->h_proto == bpf_ntohs(ETH_P_ARP))
	{
		struct arphdr *arp = (data + sizeof(*eth));

		if (data + sizeof(*eth) + sizeof(*arp) > data_end)
		{
			/* The packet is malformed, the XDP_DROP return code
			 * instructs the kernel to drop it
			 */
			return XDP_DROP;
		}

		/* We only care about ARP requests */
		if (bpf_ntohs(arp->ar_op) != ARPOP_REQUEST)
			return XDP_PASS;

		/* Reserve the packet to the ring buffer */
		struct event *e;
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

		/* Can't happen */
		if (!e)
		{
			return XDP_PASS;
		}

		e->ts = bpf_ktime_get_ns();
		e->ifindex = ctx->ingress_ifindex;
		/* Copy fields from packet to the event struct */
		memcpy(e->ar_sha, arp->ar_sha, sizeof(e->ar_sha));
		memcpy(e->ar_sip, arp->ar_sip, sizeof(e->ar_sip));
		memcpy(e->ar_tha, arp->ar_tha, sizeof(e->ar_tha));
		memcpy(e->ar_tip, arp->ar_tip, sizeof(e->ar_tip));

		/* Submit the packet to the ring buffer */
		bpf_ringbuf_submit(e, 0);
	}

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
