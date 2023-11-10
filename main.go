package main

import (
	"fmt"
	"log"
	"math/bits"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"github.com/dropbox/goebpf"
)

const Ccode string=`
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
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
    .map_type = BPF_MAP_TYPE_ARRAY,
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
`

func main() {

	// Specify Interface Name
	interfaceName := "lo"
	// IP BlockList
	// Add the IPs you want to be blocked
	ipList := []string{
		"127.0.0.1",
		"10.10.10.1",
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("./xdp.o")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	ipAdresses := bpf.GetMapByName("IP_ADDRESSES")
	if ipAdresses == nil {
		log.Fatalf("eBPF map 'IP_ADDRESSES' not found\n")
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	err = BlockIPAddress(ipList, ipAdresses)
	fmt.Println(err)
	// test := bpf.GetMapByName("IP_ADDRESSES")
	// value, _ := test.LookupInt(2130706433)
	// log.Print(value)
	// test2 := bpf.GetMapByName("STATUS")
	// time.Sleep(10 * time.Second)
	// value2, _ := test2.LookupInt(0)
	// log.Print(value2)

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfully into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC
}

// The Function That adds the IPs to the IP_ADDRESSES map
func BlockIPAddress(ipList []string, ipAddresses goebpf.Map) error {
	for _, ip := range ipList {
		newINt := bits.ReverseBytes32(IP4toInt(ip))
		err := ipAddresses.Insert(int32(newINt), uint64(1)) // Insert a dummy value

		if err != nil {
			return err
		}
	}
	return nil
}

func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

func IP4toInt(IPv4Addr string) uint32 {
	bits := strings.Split(IPv4Addr, ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32

	// left shifting 24,16,8,0 and bitwise OR

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}
