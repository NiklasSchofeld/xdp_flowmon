Work in progress.

The performance tests are done with two machines (see specs below) wich are connected via 10G ethernet interfaces.
One acts as a sender, which sends traffic to the receiver with the XDP BPF program running. For testing of the XDP_REDIRECT performance impact, a veth interface is set up on the receiver, where packets are redirected to. Every test runs for 30 seconds.

To see RAM usage, a copy of /proc/meminfo and /proc/slabinfo were taken before and while the machine is under load. Since the RAM usage primarily depends on the size of the used maps and the programs, it does not change much while running.
Duration measured with bpf_prog_test_run() is about 300ns on the receiver. This duration can change drastically on other machines. (I measured 150ns on one and >10000ns on an other)

# Sender
c3.small.x86 hosted at [equinix](equinix.com)
**CPU:** 1 x Intel(R) Xeon(R) E-2278G CPU @ 3.40GHz
**RAM:** 32GB
**OS:** Ubuntu 20.04 LTS - kernel 5.4.0-88-generic
**software:**
- [tcpreplay](https://github.com/luigirizzo/netmap/tree/master)
- [netmap](https://github.com/luigirizzo/netmap/tree/master)

# Receiver
c3.medium.x86 hosted at [equinix](equinix.com)
**CPU:** 1 x AMD EPYC 7402P 24-Core Processor @ 2.8GHz
**RAM:** 64GB
**OS:** Ubuntu 21.04 - kernel 
**software:** 
- eBPF testprogram
- nProbe
