package dns

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"testing"
)

const testDomain = "www.example.com"

func sendTestQuery(domain string) ([]byte, error) {
	UDPAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, UDPAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	query, err := buildQuery(domain, 1)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	response := buffer[:n]

	return response, nil
}

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
	// TODO: test building the query and not sending a request
	_, err := sendTestQuery(testDomain)
	if err != nil {
		t.Fatalf("Failed to send query. %s\n", err)
	}
	// fmt.Println(response)
}

func TestParseHeader(t *testing.T) {
	response, err := sendTestQuery(testDomain)
	if err != nil {
		t.Fatalf("Failed to send query. %s\n", err)
	}
	reader := bytes.NewReader(response)
	_, err = parseHeader(reader)
	// fmt.Printf("header received: %+v\n", header)
}

func TestParseName(t *testing.T) {
	response, err := sendTestQuery(testDomain)
	if err != nil {
		t.Fatalf("Failed to send query: %s\n", err)
	}
	reader := bytes.NewReader(response)
	_, err = parseHeader(reader)
	if err != nil {
		t.Fatalf("Failed to parse header: %s\n", err)
	}
	query := make([]byte, 21)
	_, err = reader.Read(query)
	if err != nil {
		t.Fatalf("Failed to parse header: %s\n", err)
	}
	// fmt.Printf("%v bytes read from response\n", n)
	// fmt.Printf("response query: %s\n", query)
	// fmt.Printf("header received: %+v\n", header)
}

func TestParseQuestion(t *testing.T) {
	response, err := sendTestQuery(testDomain)
	if err != nil {
		t.Fatalf("Failed to send query: %s\n", err)
	}
	fmt.Printf("response: %0 x\n", response)
	responseReader := bytes.NewReader(response)

	_, err = parseHeader(responseReader)
	if err != nil {
		t.Fatalf("Failed to parse header: %s\n", err)
	}

	question, err := parseQuestion(responseReader)
	fmt.Printf("domain name: %s\n", question.name)
	fmt.Printf("question: %+v\n", question)
	query := make([]byte, 16)
	n, err := responseReader.Read(query)
	if err != nil {
		t.Fatalf("Failed to parse header: %s\n", err)
	}

	fmt.Printf("%v bytes read from response\n", n)
	fmt.Printf("response query: %0 x\n", query)
}

func TestParseRecord(t *testing.T) {
	response, err := sendTestQuery(testDomain)
	if err != nil {
		t.Fatalf("Failed to send query: %s\n", err)
	}
	fmt.Printf("response: %0 x\n", response)
	reader := bytes.NewReader(response)

	_, err = parseHeader(reader)
	if err != nil {
		t.Fatalf("Failed to parse header: %s\n", err)
	}

	_, err = parseQuestion(reader)
	if err != nil {
		t.Fatalf("Failed to parse question: %s\n", err)
	}

	record, err := parseRecord(reader)
	if err != nil {
		t.Fatalf("Failed to parse record: %s\n", err)
	}

	fmt.Printf("domain name: %s\n", record.name)
	fmt.Printf("data: %0x\n", record.data)
	fmt.Printf("record: %+v\n", record)
}

func TestParsePacket(t *testing.T) {
	response, err := sendTestQuery(testDomain)
	if err != nil {
		t.Fatalf("Failed to send query: %s\n", err)
	}

	fmt.Printf("response length: %v\n", len(response))
	fmt.Printf("response: %0 x\n", response)
	// fmt.Printf("response domain name: %0 x\n", response[12:30])

	packet, err := parseDNSPacket(response)
	if err != nil {
		t.Fatalf("Failed to parse packet: %s\n", err)
	}
	fmt.Printf("packet: %+v\n", packet)

	ip := ipToStr(packet.answers[0].data)
	fmt.Printf("packet data: %s\n", ip)

	// fmt.Printf("%0x\n", 0b1100_0000)
	// fmt.Printf("%0x\n", 0b0011_1111)
}

func TestLookupDomain(t *testing.T) {
	const ipAddress = "8.8.8.8"
	const recordType = 1
	ip := lookupDomain(ipAddress, "example.com", recordType)
	fmt.Printf("ip: %s\n", ip)
	ip = lookupDomain(ipAddress, "recurse.com", recordType)
	fmt.Printf("ip: %s\n", ip)
	ip = lookupDomain(ipAddress, "metafilter.com", recordType)
	fmt.Printf("ip: %s\n", ip)
}

func TestSendQuery(t *testing.T) {
	// packet, err := sendQuery("8.8.8.8", "example.com", 1)
	// if err != nil {
	// 	t.Fatalf("Failed to send query: %s", err)
	// }
	// fmt.Printf("answers: %+v\n", packet.answers[0])

	// ip := "198.41.0.4"
	// ip := "192.12.94.30"
	// ip := "216.239.34.10"
	ip := "216.239.32.10"
	// ip := "142.251.116.139"

	response, err := sendQuery(ip, "google.com", typeA)
	fmt.Printf("%+v\n", response.answers)
	fmt.Printf("data: %s\n", response.answers[0].data)

	if err != nil {
		t.Fatalf("Failed to send query: %s", err)
	}
	fmt.Println("AUTHORITIES")
	for _, auth := range response.authorities {
		fmt.Printf("%+v\n", auth)
		fmt.Printf("data: %s\n", auth.data)
	}
	fmt.Println("ADDITIONALS")
	for _, add := range response.additionals {
		fmt.Printf("%+v\n", add)
		fmt.Printf("data: %s\n", add.data)
	}
}

func TestResolve(t *testing.T) {
	ip, err := resolve("twitter.com", typeA)
	if err != nil {
		t.Fatalf("Failed to resolve: %s", err)
	}
	fmt.Printf("ip: %s\n", ip)
}
