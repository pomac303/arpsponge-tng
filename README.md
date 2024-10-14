# About arpsponge-tng (a.k.a. "Bobby")

A implementation based on the ideea of 'arpsonge' by 
AMS-IX (https://github.com/AMS-IX/arpsponge) but also 
diffrerent. It's mplemented in C using XDP/BPF with a 
ringbuffer to get the ARP traffic to be processed.

It also uses a leaky bucket approach, to respond to the 
most noisy ARP requests...

This is important when you have a L3 network terminating
on L2 - read cloud or anything where you don't actually
use all ip addresses.

## Requirements

* gcc
* clang
* libbpf
* libxdp
* glib

and all related dev packages, including kernel
