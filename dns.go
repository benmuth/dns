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

// class DNSHeader:
//     id: int
//     flags: int
//     num_questions: int = 0
//     num_answers: int = 0
//     num_authorities: int = 0
//     num_additionals: int = 0

type DNSHeader struct {
	id             uint16
	flags          uint16
	numQuestions   uint16
	numAnswers     uint16
	numAuthorities uint16
	numAdditionals uint16
}

type DNSQuestion struct {
	name  []byte
	type_ uint16
	class uint16
}

func headerToBytes(header DNSHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func questionToBytes(question DNSQuestion) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, [2]uint16{question.type_, question.class})
	if err != nil {
		return nil, err
	}
	return append(question.name, buf.Bytes()...), nil
}

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

const TYPE_A = 1
const CLASS_IN = 1

func buildQuery(domainName string, recordType uint16) ([]byte, error) {
	name, err := encodeDNSName(domainName)
	if err != nil {
		panic(err)
	}
	id := uint16(rand.Intn(65535))
	recursionDesired := uint16(1 << 8)
	header := DNSHeader{id: id, numQuestions: 1, flags: recursionDesired}
	question := DNSQuestion{name: name, type_: recordType, class: CLASS_IN}
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

type DNSRecord struct {
	// Domain name
	name []byte
	// A, AAAA, MX, NS, TXT, etc (encoded as an int)
	type_ uint16
	// Always the same for now TODO: look up what this is
	class uint16
	// How long to cache the query
	ttl uint32
	// The record's content, like the IP Address
	data []byte
}

//	func headerToBytes(header DNSHeader) ([]byte, error) {
//		buf := new(bytes.Buffer)
//		err := binary.Write(buf, binary.BigEndian, header)
//		if err != nil {
//			return nil, err
//		}
//		return buf.Bytes(), nil
//	}
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

func decodeNameSimple(response *bytes.Reader) (string, error) {
	parts := []string{}
	length, err := response.ReadByte()
	if err != nil {
		return "", err
	}
	for length != 0 {
		nextPart := make([]byte, length)
		_, err := response.Read(nextPart)
		if err != nil {
			return "", err
		}
		parts = append(parts, string(nextPart))
		length, err = response.ReadByte()
		if err != nil {
			return "", err
		}
	}
	return strings.Join(parts, "."), nil
}

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
			break
		} else {
			nextPart = make([]byte, length)
			_, err := response.Read(nextPart)
			if err != nil {
				return "", fmt.Errorf("Failed to read next part: %w", err)
			}
		}
		parts = append(parts, string(nextPart))
		length, err = response.ReadByte()
		if err != nil {
			return "", fmt.Errorf("Failed to read length byte: %w", err)
		}
	}
	return strings.Join(parts, "."), nil
}

// def decode_compressed_name(length, reader):
//     pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
//     pointer = struct.unpack("!H", pointer_bytes)[0]
//     current_pos = reader.tell()
//     reader.seek(pointer)
//     result = decode_name(reader)
//     reader.seek(current_pos)
//     return result

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

// def parse_record(reader):
//     name = decode_name_simple(reader)
//     # the the type, class, TTL, and data length together are 10 bytes (2 + 2 + 4 + 2 = 10)
//     # so we read 10 bytes
//     data = reader.read(10)
//     # HHIH means 2-byte int, 2-byte-int, 4-byte int, 2-byte int
//     type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
//     data = reader.read(data_len)
//     return DNSRecord(name, type_, class_, ttl, data)

func parseRecord(response *bytes.Reader) (DNSRecord, error) {
	name, err := decodeName(response)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("Failed to decode name: %w", err)
	}
	metaData := make([]byte, 10)
	_, err = response.Read(metaData)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("Failed to read metadata: %w", err)
	}
	dataLen := binary.BigEndian.Uint16(metaData[8:])
	data := make([]byte, dataLen)
	n, err := response.Read(data)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("Failed to read data: %w", err)
	}
	if n != int(dataLen) {
		return DNSRecord{}, fmt.Errorf("Failed to read correct amount of bytes: expected %v, read %v", dataLen, n)
	}

	return DNSRecord{
		name:  []byte(name),
		type_: binary.BigEndian.Uint16(metaData[:2]),
		class: binary.BigEndian.Uint16(metaData[2:4]),
		ttl:   binary.BigEndian.Uint32(metaData[4:8]),
		data:  data,
	}, nil
}

// from typing import List

// @dataclass
// class DNSPacket:
//     header: DNSHeader
//     questions: List[DNSQuestion]
//     # don't worry about the exact meaning of these 3 record
//     # sections for now: we'll use them in Part 3
//     answers: List[DNSRecord]
//     authorities: List[DNSRecord]
//     additionals: List[DNSRecord]

type DNSPacket struct {
	header    DNSHeader
	questions []DNSQuestion
	// don't worry about the exact meaning of these 3 record
	// sections for now: we'll use them in Part 3
	answers     []DNSRecord
	authorities []DNSRecord
	additionals []DNSRecord
}

type IPAddr []byte

func (ip IPAddr) String() string {
	parts := make([]string, len(ip))
	for i, b := range ip {
		parts[i] = strconv.Itoa(int(b))
	}
	str := strings.Join(parts, ".")
	return str
}

// def parse_dns_packet(data):
//     reader = BytesIO(data)
//     header = parse_header(reader)
//     questions = [parse_question(reader) for _ in range(header.num_questions)]
//     answers = [parse_record(reader) for _ in range(header.num_answers)]
//     authorities = [parse_record(reader) for _ in range(header.num_authorities)]
//     additionals = [parse_record(reader) for _ in range(header.num_additionals)]

// return DNSPacket(header, questions, answers, authorities, additionals)
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

	answers := make([]DNSRecord, header.numAnswers)
	for i := 0; i < len(answers); i++ {
		a, err := parseRecord(response)
		if err != nil {
			return DNSPacket{}, fmt.Errorf("Failed to parse answer: %w", err)
		}
		answers[i] = a
	}

	authorities := make([]DNSRecord, header.numAuthorities)
	for i := 0; i < len(authorities); i++ {
		a, err := parseRecord(response)
		if err != nil {
			return DNSPacket{}, fmt.Errorf("Failed to parse authority: %w", err)
		}
		authorities[i] = a
	}

	additionals := make([]DNSRecord, header.numAdditionals)
	for i := 0; i < len(additionals); i++ {
		a, err := parseRecord(response)
		if err != nil {
			return DNSPacket{}, fmt.Errorf("Failed to parse additional: %w", err)
		}
		additionals[i] = a
	}

	return DNSPacket{
		header:      header,
		questions:   questions,
		answers:     answers,
		authorities: authorities,
		additionals: additionals,
	}, nil
}

func sendQuery(domain string) ([]byte, error) {
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

// TODO: This prints the wrong IP address if the domain contains 'www'
// HINT: Look at the record type!
func lookupDomain(domain string) string {
	response, err := sendQuery(domain)
	if err != nil {
		fmt.Printf("Failed to send query: %s\n", err)
	}

	packet, err := parseDNSPacket(response)
	if err != nil {
		fmt.Printf("Failed to parse packet: %s\n", err)
	}
	// fmt.Printf("raw ip data: %d\n", packet.answers[0].data)
	ip := IPAddr(packet.answers[0].data)
	return ip.String()
}

func main() {
	// fmt.Println("Hello world!")
	// header := DNSHeader{
	// 	1, 2, 3, 4, 5, 6,
	// }
	// headerToBytes(header)
}
