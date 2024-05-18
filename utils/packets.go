package utils

import (
	"crypto/rand"
	"encoding/binary"
	"log"
)

type MessagePackage struct {
	PacketLength  uint32
	PaddingLength uint32
	Payload       []byte // packet_length - padding_length - 1
	RandomPadding []byte // n2 = padding_length
	MAC           []byte // m = mac_length
}

// ParseMessagePackage parses a raw SSH message into a MessagePackage struct.
func ParseMessagePackage(keyExchangeMsg []byte) MessagePackage {
	// Create an empty MessagePackage
	messagePackage := MessagePackage{}

	// Packet Length
	packetLength := binary.BigEndian.Uint32(keyExchangeMsg[:4])
	messagePackage.PacketLength = packetLength

	// Padding Length
	paddingLength := keyExchangeMsg[4]
	messagePackage.PaddingLength = uint32(paddingLength)

	// Payload
	payload := keyExchangeMsg[5 : packetLength-uint32(paddingLength)-1]
	messagePackage.Payload = payload

	// Random Padding
	randomPadding := keyExchangeMsg[packetLength-uint32(paddingLength)-1 : packetLength-1]
	messagePackage.RandomPadding = randomPadding

	// MAC
	mac := keyExchangeMsg[packetLength-1:]
	messagePackage.MAC = mac

	return messagePackage
}

// CreateSSHMessage creates a properly formatted SSH message from a given payload.
func CreateSSHMessage(payload []byte) []byte {
	const blockSize = 8

	// Create initial padding of 4 bytes
	paddingLength := 4
	padding := make([]byte, paddingLength)
	if _, err := rand.Read(padding); err != nil {
		log.Fatalf("Failed to generate random padding: %v", err)
	}

	// Calculate initial packet length
	packetLength := calculatePacketLength(payload, paddingLength)

	// Adjust padding length to make total length a multiple of blockSize
	for packetLength%blockSize != 0 {
		paddingLength++
		padding = make([]byte, paddingLength)
		if _, err := rand.Read(padding); err != nil {
			log.Fatalf("Failed to generate random padding: %v", err)
		}
		packetLength = calculatePacketLength(payload, paddingLength)
	}

	// Create the final message
	messageToClient := make([]byte, packetLength)
	binary.BigEndian.PutUint32(messageToClient[:4], uint32(packetLength-4)) // packet_length does not include itself
	messageToClient[4] = byte(paddingLength)
	copy(messageToClient[5:], payload)
	copy(messageToClient[5+len(payload):], padding)

	return messageToClient
}

// calculatePacketLength computes the total packet length.
func calculatePacketLength(payload []byte, paddingLength int) int {
	// packet_length (4 bytes) + padding_length (1 byte) + payload + padding
	return 4 + 1 + len(payload) + paddingLength
}
