package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

const (
	typeA   = 1
	typeNS  = 2
	typeTXT = 16
	classIn = 1
)

// A DNSHeader is the first part of a DNS query
type DNSHeader struct {
	// the id is a random ID for the query
	id uint16
	// flags indicate different options, like whether to use recursion
	flags uint16

	// the following 4 fields indicate how many records to expect in each
	// section of a DNS packet

	numQuestions   uint16
	numAnswers     uint16
	numAuthorities uint16
	numAdditionals uint16
}

// A DNSQuestion is the second part of a DNS query
type DNSQuestion struct {
	// name is the domain name (like example.com)
	name []byte
	// type_ indicates the type of record (like A, AAAA, NS, etc.)
	type_ uint16
	class uint16
}

// A DNSRecord represents the answer to a DNS query
type DNSRecord struct {
	// name is the domain name (like example.com)
	name []byte
	// type_ indicates the type of record (like A, AAAA, NS, etc.) encoded
	// as an int
	type_ uint16
	// class is always the same for now TODO: look up what this is
	class uint16
	// ttl indicates how long to cache the query
	ttl uint32
	// data holds the record's content, like the IP Address
	data []byte
}

// DNSPacket holds the data from an entire DNS response
type DNSPacket struct {
	header    DNSHeader
	questions []DNSQuestion
	// answers holds the records that directly answer the DNS question in the
	// original query
	answers []DNSRecord
	// authorities holds the records for the authoritative name servers for
	// the given domain
	authorities []DNSRecord
	// additionals holds records with potentially useful additional information
	additionals []DNSRecord
}

// headerToBytes converts a DNSHeader to bytes
func headerToBytes(header DNSHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// questionToBytes converts a DNSquestion to bytes
func questionToBytes(question DNSQuestion) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, [2]uint16{question.type_, question.class})
	if err != nil {
		return nil, err
	}
	return append(question.name, buf.Bytes()...), nil
}

// encodeDNSName converts a name like 'google.com' to "\x06google\x03com\x00"
// where each part is prepended with its length
func encodeDNSName(domain string) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, part := range strings.Split(domain, ".") {
		_ = buf.WriteByte(byte(len(part)))
		if _, err := buf.WriteString(part); err != nil {
			return nil, err
		}
	}
	_ = buf.WriteByte(0)
	return buf.Bytes(), nil
}

func buildQuery(domainName string, recordType uint16) ([]byte, error) {
	name, err := encodeDNSName(domainName)
	if err != nil {
		panic(err)
	}
	id := uint16(rand.Intn(65535))
	header := DNSHeader{id: id, numQuestions: 1, flags: 0}
	question := DNSQuestion{name: name, type_: recordType, class: classIn}
	headerBytes, err := headerToBytes(header)
	if err != nil {
		return nil, err
	}
	questionBytes, err := questionToBytes(question)
	if err != nil {
		return nil, err
	}
	return append(headerBytes, questionBytes...), nil
}

// parseHeader reads from a response to a DNS query and returns a DNSHeader.
// parseHeader should be called before parseQuestion or parseRecord.
func parseHeader(response *bytes.Reader) (DNSHeader, error) {
	const DNSHeaderSize = 12
	headerBytes := make([]byte, DNSHeaderSize)
	n, err := response.Read(headerBytes)
	if err != nil {
		return DNSHeader{}, err
	}
	if n != DNSHeaderSize {
		return DNSHeader{}, errors.New("not enough data to read the full DNS header")
	}

	header := DNSHeader{
		id:             binary.BigEndian.Uint16(headerBytes[:2]),
		flags:          binary.BigEndian.Uint16(headerBytes[2:4]),
		numQuestions:   binary.BigEndian.Uint16(headerBytes[4:6]),
		numAnswers:     binary.BigEndian.Uint16(headerBytes[6:8]),
		numAuthorities: binary.BigEndian.Uint16(headerBytes[8:10]),
		numAdditionals: binary.BigEndian.Uint16(headerBytes[10:]),
	}

	return header, nil
}

// decodeName decodes a (possibly compressed) DNS name.
func decodeName(response *bytes.Reader) (string, error) {
	parts := []string{}
	length, err := response.ReadByte()
	if err != nil {
		return "", fmt.Errorf("Failed to read first byte: %w", err)
	}
	for length != 0 {
		var nextPart []byte
		if (length & 0b1100_0000) > 0 {
			nextPart, err = decodeCompressedName(length, response)
			if err != nil {
				return "", fmt.Errorf("Failed to decode compressed name: %w", err)
			}
			parts = append(parts, string(nextPart))
			break
		} else {
			nextPart = make([]byte, length)
			_, err := response.Read(nextPart)
			if err != nil {
				return "", fmt.Errorf("Failed to read next part: %w", err)
			}
			parts = append(parts, string(nextPart))
		}
		length, err = response.ReadByte()
		if err != nil {
			return "", fmt.Errorf("Failed to read length byte: %w", err)
		}
	}
	return strings.Join(parts, "."), nil
}

// decodeCompressedName is a helper function for decodeName.
func decodeCompressedName(length byte, response *bytes.Reader) ([]byte, error) {
	nextByte, err := response.ReadByte()
	if err != nil {
		return nil, err
	}
	pointerBytes := []byte{length & 0b0011_1111, nextByte}
	pointer := binary.BigEndian.Uint16(pointerBytes)
	currentPos, err := response.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	_, err = response.Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return nil, err
	}
	result, err := decodeName(response)
	if err != nil {
		return nil, err
	}
	currentPos, err = response.Seek(currentPos, io.SeekStart)
	if err != nil {
		return nil, err
	}
	return []byte(result), nil
}

// parseQuestion reads from a response to a DNS query and returns a
// DNSQuestion. parseQuestion should be called after parseHeader and
// before parseRecord.
func parseQuestion(response *bytes.Reader) (DNSQuestion, error) {
	name, err := decodeName(response)
	if err != nil {
		return DNSQuestion{}, err
	}
	data := make([]byte, 4)
	_, err = response.Read(data)
	if err != nil {
		return DNSQuestion{}, err
	}

	return DNSQuestion{
		name:  []byte(name),
		type_: binary.BigEndian.Uint16(data[:2]),
		class: binary.BigEndian.Uint16(data[2:]),
	}, nil
}

// parseRecord reads from a response to a DNS query and returns a DNSRecord.
// parseRecord should be called after parseHeader and parseQuestion.
func parseRecord(response *bytes.Reader) (DNSRecord, error) {
	name, err := decodeName(response)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("Failed to decode name: %w", err)
	}
	// the the type, class, TTL, and data length together are 10 bytes (2 + 2 + 4 + 2 = 10)
	metaData := make([]byte, 10)
	_, err = response.Read(metaData)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("Failed to read metadata: %w", err)
	}

	dataLen := binary.BigEndian.Uint16(metaData[8:])
	data := make([]byte, dataLen)
	type_ := binary.BigEndian.Uint16(metaData[:2])
	if type_ == typeNS {
		name, err := decodeName(response)
		if err != nil {
			return DNSRecord{}, nil
		}
		data = []byte(name)
	} else {
		_, err := response.Read(data)
		if err != nil {
			return DNSRecord{}, fmt.Errorf("Failed to read data: %w", err)
		}

		if type_ == typeA {
			data = []byte(ipToStr(data))
		}
	}
	return DNSRecord{
		name:  []byte(name),
		type_: type_,
		class: binary.BigEndian.Uint16(metaData[2:4]),
		ttl:   binary.BigEndian.Uint32(metaData[4:8]),
		data:  data,
	}, nil
}

// parseSection parses n records from response
func parseSection(n uint16, response *bytes.Reader) ([]DNSRecord, error) {
	records := make([]DNSRecord, n)
	for i := 0; i < len(records); i++ {
		r, err := parseRecord(response)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse record: %w", err)
		}
		records[i] = r
	}
	return records, nil
}

// parseDNSPacket parses a response to a DNS query
func parseDNSPacket(responseBytes []byte) (DNSPacket, error) {
	response := bytes.NewReader(responseBytes)
	header, err := parseHeader(response)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("Failed to parse header: %w", err)
	}
	questions := make([]DNSQuestion, header.numQuestions)
	for i := 0; i < len(questions); i++ {
		q, err := parseQuestion(response)
		if err != nil {
			return DNSPacket{}, fmt.Errorf("Failed to parse question: %w", err)
		}
		questions[i] = q
	}

	answers, err := parseSection(header.numAnswers, response)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("Failed to parse answer: %w", err)
	}

	authorities, err := parseSection(header.numAuthorities, response)

	additionals, err := parseSection(header.numAdditionals, response)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("Failed to parse answer: %w", err)
	}

	return DNSPacket{
		header:      header,
		questions:   questions,
		answers:     answers,
		authorities: authorities,
		additionals: additionals,
	}, nil
}

// sendQuery sends a DNS query for the given domain to the given ipAddress
func sendQuery(ipAddress string, domain string, recordType uint16) (DNSPacket, error) {
	UDPAddr, err := net.ResolveUDPAddr("udp", ipAddress+":53")
	if err != nil {
		return DNSPacket{}, err
	}

	conn, err := net.DialUDP("udp", nil, UDPAddr)
	if err != nil {
		return DNSPacket{}, err
	}
	defer conn.Close()

	query, err := buildQuery(domain, recordType)
	if err != nil {
		return DNSPacket{}, err
	}
	_, err = conn.Write(query)
	if err != nil {
		return DNSPacket{}, err
	}

	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return DNSPacket{}, err
	}

	response := buffer[:n]

	return parseDNSPacket(response)
}

func getAnswer(packet DNSPacket) string {
	for _, x := range packet.answers {
		if x.type_ == typeA {
			return string(x.data)
		}
	}
	return ""
}

func getNameserverIp(packet DNSPacket) string {
	for _, x := range packet.additionals {
		if x.type_ == typeA {
			return string(x.data)
		}
	}
	return ""
}

func getNameserver(packet DNSPacket) string {
	for _, x := range packet.authorities {
		if x.type_ == typeNS {
			return string(x.data)
		}
	}
	return ""
}

// resolve returns the ip address for a given domainName
func resolve(domainName string, recordType int) (string, error) {
	nameserver := ("198.41.0.4")
	for {
		fmt.Printf("querying %s for %s\n", nameserver, domainName)
		response, err := sendQuery(nameserver, domainName, uint16(recordType))
		if err != nil {
			return "", err
		}

		if ip := getAnswer(response); ip != "" {
			return ip, nil
		} else if nsIp := getNameserverIp(response); nsIp != "" {
			nameserver = nsIp
		} else if nsDomain := getNameserver(response); nsDomain != "" {
			nameserver, err = resolve(nsDomain, typeA)
			if err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("couldn't resolve")
		}
	}
}

// BUG: This prints the wrong IP address if the domain contains 'www'
// HINT: Look at the record type!
func lookupDomain(ipAddress string, domain string, recordType uint16) string {
	packet, err := sendQuery(ipAddress, domain, recordType)
	if err != nil {
		fmt.Printf("Failed to parse packet: %s\n", err)
	}
	ip := packet.answers[0].data
	return ipToStr(ip)
}

func ipToStr(ip []byte) string {
	parts := make([]string, len(ip))
	for i, b := range ip {
		parts[i] = strconv.Itoa(int(b))
	}
	str := strings.Join(parts, ".")
	return str
}

func (rec DNSRecord) String() string {
	return fmt.Sprintf("name: %s\tdata: %s\n", rec.name, rec.data)
}
