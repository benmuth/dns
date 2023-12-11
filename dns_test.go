package dns

import (
	"fmt"
	"net"
	"reflect"
	"testing"
)

func TestEncodeDNSName(t *testing.T) {
	tests := []struct {
		domain string
		want   []byte
	}{
		{
			domain: "google.com",
			want:   []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			got, err := encodeDNSName(tc.domain)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.want, got) {
				t.Errorf("Failed to encode DNS name. Want %v\t Got %v\n", tc.want, got)
			}
		})
	}
}

func TestBuildQuery(t *testing.T) {
	UDPAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, UDPAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query, err := buildQuery("www.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", query)
	n, err := conn.Write(query)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v bytes sent", n)

	buffer := make([]byte, 1024)
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Received", n, "bytes from", addr)
	response := buffer[:n]
	fmt.Printf("received response: \n%s\n", response)
}
