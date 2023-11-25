//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

#define MAX_MAP_LPM_ENTRIES 10000
#define MAX_MAP_HASH_ENTRIES 10000

char _license[4] SEC("license") = "GPL";

//Debug code
#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

/* Key for lpm_trie */
union key_4 {
	__u32 b32[2];
	__u8 b8[8];
};



struct statusMapVal {
    __u64 rx_packets;
    __u64 size_packets;
};

// struct ipv4_lpm_key {
//       __u32 prefixlen;
//       __u32 saddr;
// };

/* Map for trie implementation */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, 8);
	__uint(value_size, 1);
	__uint(max_entries, 50);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_ipv4 SEC(".maps");

struct {
	//__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, MAX_MAP_HASH_ENTRIES);
	__type(key, __u32);
	__type(value, struct statusMapVal);
} status SEC(".maps");

SEC("xdp")
int firewall(struct xdp_md *ctx){
    bpf_printk("Start XDP Firewall checking");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 packet_size = ctx->data_end-ctx->data;
    // We need to parse the ethernet header
    struct ethhdr *ether = data;
    // Check if the Ethernet header is malformed
    bpf_printk("check if Ethernet Header is Malformed or not");
    if (data + sizeof(*ether) > data_end) {
      return XDP_ABORTED;
    }
    bpf_printk("Ethernet Header is not malformed");
    //Ethernet header is not malformed
    bpf_printk("Check if IPv4 traffic");
    if (ether->h_proto != bpf_htons(ETH_P_IP)) { 
    // If not IPv4 Traffic, pass the packet
      return XDP_PASS;
    }
    bpf_printk("It is IPv4 traffic");
    //move data pointer to pass the ethernet header
    data += sizeof(*ether);
    //parse the IPv4 packet
    struct iphdr *ip = data;
    // Check if the IPv4 header is malformed
    bpf_printk("check if IPv4 Header is Malformed or not");
    if (data + sizeof(*ip) > data_end) {
      return XDP_ABORTED;
    }
    bpf_printk("IPv4 Header is not malformed");

		union key_4 ipKey;
			/* Look up in the trie for lpm */
		ipKey.b32[0] = 32;
		ipKey.b8[4] = ip->saddr & 0xff;
		ipKey.b8[5] = (ip->saddr >> 8) & 0xff;
		ipKey.b8[6] = (ip->saddr >> 16) & 0xff;
		ipKey.b8[7] = (ip->saddr >> 24) & 0xff;
    
    __u32 *pointer = bpf_map_lookup_elem(&blocked_ipv4, &ipKey);
    bpf_printk("pointer value is: %p", pointer);
    if (pointer != NULL){
      bpf_printk("IP is blocked");
      __be32 ip_src_addr = (*ip).saddr;
      struct statusMapVal *stats_element = bpf_map_lookup_elem(&status, &ip_src_addr);  
      if (stats_element != NULL){
          stats_element->rx_packets += 1;
          stats_element->size_packets += packet_size;
          bpf_printk("Item Incremented");
      } else {
        struct statusMapVal newData;
        newData.rx_packets = 1;
        newData.size_packets = packet_size;
        // __u32 ipAddr = bpf_ntohl(ip->saddr);
        bpf_map_update_elem(&status, &ip_src_addr, &newData, BPF_ANY);
        bpf_printk("New Item Created");

      }
      // bpf_printk("Status map rx_packets value is: %llx",stats_element->rx_packets);
      // bpf_printk("Status map size_packets value is: %llx",stats_element->size_packets);
      return XDP_DROP;
    }
    return XDP_PASS;
} 
