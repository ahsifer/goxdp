package helpers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func Error(response http.ResponseWriter, message string, status int) {
	http.Error(response, fmt.Sprintf(`{ "status": %d, "message": "%s" }`, status, message), status)
}

// Check if the IP address is valid or not
func IpChecker(ip string) (*string, error) {
	if !strings.Contains(ip, "/") {
		ip += "/32"
	}
	if strings.Contains(ip, ":") {
		return nil, errors.New("is not an IPv4 address")
	}
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		return nil, err
	}
	// ip=bits.Reverse64(ip)

	return &ip, nil
}

func IP4toInt(IPv4Addr string) (*uint32, error) {
	bits := strings.Split(IPv4Addr, ".")

	b0, err := strconv.Atoi(bits[0])
	if err != nil {
		return nil, err
	}
	b1, err := strconv.Atoi(bits[1])
	if err != nil {
		return nil, err
	}
	b2, err := strconv.Atoi(bits[2])
	if err != nil {
		return nil, err
	}
	b3, err := strconv.Atoi(bits[3])
	if err != nil {
		return nil, err
	}

	var sum uint32

	// left shifting 24,16,8,0 and bitwise OR
	//big endian conversion
	sum += uint32(b3) << 24
	sum += uint32(b2) << 16
	sum += uint32(b1) << 8
	sum += uint32(b0)

	return &sum, nil
}

func IntToIPv4(decimal uint32) string {
	output := ""
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, decimal)
	output = fmt.Sprintf("%v.%v.%v.%v", bs[0], bs[1], bs[2], bs[3])
	return output
}

func Ipv4Reverse(IPv4Addr string) string {
	bits := strings.Split(IPv4Addr, ".")
	outString := bits[0] + "." + bits[1] + "." + bits[2] + "." + bits[3]
	return outString

}
