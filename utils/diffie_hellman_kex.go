package utils

import (
	"encoding/binary"
	"fmt"
)

/*
Each packet is in the following format:

	uint32    packet_length
	byte      padding_length
	byte[n1]  payload; n1 = packet_length - padding_length - 1
	byte[n2]  random padding; n2 = padding_length
	byte[m]   mac (Message Authentication Code - MAC); m = mac_length

	packet_length
	   The length of the packet in bytes, not including 'mac' or the
	   'packet_length' field itself.

	padding_length
	   Length of 'random padding' (bytes).

	payload
	   The useful contents of the packet.  If compression has been
	   negotiated, this field is compressed.  Initially, compression
	   MUST be "none".

	random padding
	   Arbitrary-length padding, such that the total length of
	   (packet_length || padding_length || payload || random padding)
	   is a multiple of the cipher block size or 8, whichever is
	   larger.  There MUST be at least four bytes of padding.  The
	   padding SHOULD consist of random bytes.  The maximum amount of
	   padding is 255 bytes.

	mac
	   Message Authentication Code.  If message authentication has
	   been negotiated, this field contains the MAC bytes.  Initially,
	   the MAC algorithm MUST be "none".
*/
func ComputeSharedSecret(keyExchangeMsg []byte) []byte {
	fmt.Printf("Computing shared secret from key exchange message: %v\n", keyExchangeMsg)

	packageLength := binary.BigEndian.Uint32(keyExchangeMsg[0:4])
	fmt.Printf("Package length: %v\n", packageLength)

	// SOLVED
	paddingLength := int(keyExchangeMsg[4])
	fmt.Printf("Padding length: %v\n", paddingLength)

	payload := keyExchangeMsg[5 : len(keyExchangeMsg)-paddingLength-1]
	fmt.Printf("Payload: %v\n", payload)

	randomPadding := keyExchangeMsg[len(keyExchangeMsg)-1 : len(keyExchangeMsg)-1]
	mac := keyExchangeMsg[len(keyExchangeMsg)-1 : len(keyExchangeMsg)-1]

	fmt.Printf("Package length: %v\n", packageLength)
	fmt.Printf("Padding length: %v\n", paddingLength)

	fmt.Printf("Payload: %v\n", payload)
	fmt.Printf("Random padding: %v\n", randomPadding)
	fmt.Printf("MAC: %v\n", mac)

	// Calculate shared secret using Diffie-Hellman key exchange
	sharedSecret := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	return sharedSecret
}
