#ifndef __COMMON_H
#define __COMMON_H

/* definition of a sample sent to user-space from BPF program */
struct event {
	u_int64_t ts;		/* timestamp */
	u_int32_t ifindex;	/* interface index */
	u_int16_t ar_op;	/* ARP opcode */
	u_int8_t ar_sha[6];	/* sender hardware address	*/
	u_int8_t ar_sip[4];	/* sender IP address		*/
	u_int8_t ar_tha[6];	/* target hardware address	*/
	u_int8_t ar_tip[4];	/* target IP address		*/
};

#endif /* __COMMON_H */
