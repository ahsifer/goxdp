#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
struct datarec {
	__u64 rx_packets;
  __u64 size_packets;
  __u32 saddr;
};
BPF_MAP_DEF(IP_ADDRESSES) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 16,
};
BPF_MAP_ADD(IP_ADDRESSES);
BPF_MAP_DEF(STATUS) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct datarec),
    .max_entries = 16,
};
BPF_MAP_ADD(STATUS);
SEC("xdp") /* marks main eBPF program entry point */
int firewall(struct xdp_md *ctx){
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
// We need to parse the eathernet header
  struct ethhdr *ether = data;
  // Check if the Ethernet header is malformed
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }
  //Earthernet header is not malformed
  if (ether->h_proto != 0x08U) { 
    // If not IPv4 Traffic, pass the packet
    return XDP_PASS;
  }
  data += sizeof(*ether);
  struct iphdr *ip = data;
  // Check if the IPv4 header is malformed
  if (data + sizeof(*ip) > data_end) {
    return XDP_ABORTED;
  }
  __u64 sourcIP = ip->saddr;
  __u64 *p = bpf_map_lookup_elem(&IP_ADDRESSES, &sourcIP);
  if (p != 0){
  struct datarec *stats_element = bpf_map_lookup_elem(&STATUS, &sourcIP);
  if (stats_element){
      stats_element->saddr = ip->saddr;
      stats_element->rx_packets += 1;
      stats_element->size_packets += data_end - data;
  }
    return XDP_DROP;
  }
  return XDP_PASS;
}