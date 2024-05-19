package keyExchange

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"jnsaph/constants"
	"log"
	"strings"
)

type SSHMsgKexdhInit struct {
	kex_algorithms                          []byte
	server_host_key_algorithms              []byte
	client_to_server_encryption_algorithms  []byte
	server_to_client_encryption_algorithms  []byte
	client_to_server_mac_algorithms         []byte
	server_to_client_mac_algorithms         []byte
	client_to_server_compression_algorithms []byte
	server_to_client_compression_algorithms []byte
	client_to_server_languages              []byte
	server_to_client_languages              []byte
	first_kex_packet_follows                byte
}

func readNameList(data []byte, index int) ([]byte, int, error) {
	if index+4 > len(data) {
		return nil, index, fmt.Errorf("index out of bounds")
	}

	length := binary.BigEndian.Uint32(data[index : index+4])
	index += 4

	if index+int(length) > len(data) {
		return nil, index, fmt.Errorf("index out of bounds")
	}

	str := data[index : index+int(length)]
	index += int(length)

	return str, index, nil
}

func ParseSSHMsgKexinit(packet []byte) SSHMsgKexdhInit {
	// Skip SSH_MSG_KEXINIT byte and cookie (which should only add up to 17 bytes? Right? idk this works tho)
	// Currently:
	// 4 byte packet length
	// 1 byte padding length
	// 1 Byte is the SSH_MSG_KEXINIT byte
	// 16 Bytes is the cookie
	// Total 22. fuck me
	data := packet[22:]

	index := 0

	kex_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading kex_algos: %v", err)
	}

	server_host_key_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading server_host_key_algorithms: %v", err)
	}

	client_to_server_encryption_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading client_to_server_encryption_algorithms: %v", err)
	}

	server_to_client_encryption_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading server_to_client_encryption_algorithms: %v", err)
	}

	client_to_server_mac_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading client_to_server_mac_algorithms: %v", err)
	}

	server_to_client_mac_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading server_to_client_mac_algorithms: %v", err)
	}

	client_to_server_compression_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading client_to_server_compression_algorithms: %v", err)
	}

	server_to_client_compression_algorithms, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading server_to_client_compression_algorithms: %v", err)
	}
	client_to_server_languages, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading client_to_server_languages: %v", err)
	}

	server_to_client_languages, index, err := readNameList(data, index)
	if err != nil {
		log.Fatalf("Error reading server_to_client_languages: %v", err)
	}

	first_kex_packet_follows := data[index]

	return SSHMsgKexdhInit{
		kex_algorithms:                          kex_algorithms,
		server_host_key_algorithms:              server_host_key_algorithms,
		client_to_server_encryption_algorithms:  client_to_server_encryption_algorithms,
		server_to_client_encryption_algorithms:  server_to_client_encryption_algorithms,
		client_to_server_mac_algorithms:         client_to_server_mac_algorithms,
		server_to_client_mac_algorithms:         server_to_client_mac_algorithms,
		client_to_server_compression_algorithms: client_to_server_compression_algorithms,
		server_to_client_compression_algorithms: server_to_client_compression_algorithms,
		client_to_server_languages:              client_to_server_languages,
		server_to_client_languages:              server_to_client_languages,
		first_kex_packet_follows:                first_kex_packet_follows,
	}
}

func getCommonAlgorithms(nameList []byte, supportedAlgorithms []string) []byte {
	var supportedAlgos []string

	nameListStr := string(nameList)
	splitNameList := strings.Split(nameListStr, ",")

	for _, algo := range splitNameList {
		for _, supportedAlgo := range supportedAlgorithms {
			if algo == supportedAlgo {
				supportedAlgos = append(supportedAlgos, algo)
			}
		}
	}

	// Check if any common algorithms were found
	if len(supportedAlgos) == 0 {
		log.Fatalf("No common algorithms found! \nSupported algorithms: %v\nNameList: %s", supportedAlgorithms, nameListStr)
	}

	// combine the supported algorithms into a single string
	combinedAlgos := strings.Join(supportedAlgos, ",")
	lengthPrefix := uint32(len(combinedAlgos))

	// create a byte slice to hold the length prefix
	lengthPrefixBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthPrefixBytes, lengthPrefix)

	// concatenate the length prefix and the combined algorithms
	result := append(lengthPrefixBytes, []byte(combinedAlgos)...)

	return result
}

func CreateSSHMsgKexinit(SSH_MSG_KEXINIT_Client SSHMsgKexdhInit) ([]byte, error) {
	firstKexPacketFollows := SSH_MSG_KEXINIT_Client.first_kex_packet_follows

	// first byte should be 20
	SSH_MSG_KEXINIT_Server := []byte{20}

	// add 16 bytes of random data
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
		return nil, err
	}

	// Append the random bytes (cookie) to SSH_MSG_KEXINIT_Server
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, randomBytes...)

	// Add kex_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.kex_algorithms, constants.SUPPORTED_KEX_ALGORITHMS)...)

	// Add server_host_key_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.server_host_key_algorithms, constants.SUPPORTED_SERVER_HOST_KEY_ALGORITHMS)...)

	// Add client_to_server_encryption_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.client_to_server_encryption_algorithms, constants.SUPPORTED_CLIENT_TO_SERVER_ENCRYPTION_ALGORITHMS)...)

	// Add server_to_client_encryption_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.server_to_client_encryption_algorithms, constants.SUPPORTED_SERVER_TO_CLIENT_ENCRYPTION_ALGORITHMS)...)

	// Add client_to_server_mac_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.client_to_server_mac_algorithms, constants.SUPPORTED_CLIENT_TO_SERVER_MAC_ALGORITHMS)...)

	// Add server_to_client_mac_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.server_to_client_mac_algorithms, constants.SUPPORTED_SERVER_TO_CLIENT_MAC_ALGORITHMS)...)

	// Add client_to_server_compression_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.client_to_server_compression_algorithms, constants.SUPPORTED_CLIENT_TO_SERVER_COMPRESSION_ALGORITHMS)...)

	// Add server_to_client_compression_algorithms
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, getCommonAlgorithms(SSH_MSG_KEXINIT_Client.server_to_client_compression_algorithms, constants.SUPPORTED_SERVER_TO_CLIENT_COMPRESSION_ALGORITHMS)...)

	// Add client_to_server_languages (with length prefix 0)
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, []byte{0, 0, 0, 0}...)

	// Add server_to_client_languages (with length prefix 0)
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, []byte{0, 0, 0, 0}...)

	// Add first_kex_packet_follows
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, firstKexPacketFollows)

	// Add reserved (4 bytes of 0)
	SSH_MSG_KEXINIT_Server = append(SSH_MSG_KEXINIT_Server, []byte{0, 0, 0, 0}...)

	return SSH_MSG_KEXINIT_Server, nil
}
