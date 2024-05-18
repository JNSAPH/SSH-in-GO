package handlers

import (
	"crypto/rsa"
	"fmt"
	"jnsaph/constants"
	"jnsaph/keyExchange"
	"jnsaph/utils"
	"log"
	"net"
)

// RFC 4253 for details: https://tools.ietf.org/html/rfc4253
func HandleSSHConnection(conn net.Conn, privateKey *rsa.PrivateKey) {
	defer conn.Close()

	log.Println("=== SSH Connection ===")
	log.Printf("SSH connection established from %s", conn.RemoteAddr())

	// ID-String exchange Client -> Server
	idString := make([]byte, 1024)
	n, err := conn.Read(idString)
	if err != nil {
		log.Printf("Error reading ID-String: %v", err)
		return
	}
	log.Printf("ID-String from Client: %s\n", idString[:n])

	// ID-String exchange Server -> Client
	banner := constants.IDStringBanner
	conn.Write([]byte(banner + "\r\n"))

	// SSH_MSG_KEXINIT Client -> Server
	keyExchangeMsg := make([]byte, 4096)
	n, err = conn.Read(keyExchangeMsg)
	if err != nil {
		log.Printf("Error reading Key Exchange Message: %v", err)
		return
	}

	SSH_MSG_KEXINIT_Client := keyExchange.ParseSSHMsgKexinit(keyExchangeMsg[:n])

	// SSH_MSG_KEXINIT Server -> Client
	SSH_MSG_KEXINIT_Server, err := keyExchange.CreateSSHMsgKexinit(SSH_MSG_KEXINIT_Client)
	if err != nil {
		log.Fatalf("Error creating SSH_MSG_KEXINIT: %v", err)
	}

	SSH_MSG_KEXINIT_Server = utils.CreateSSHMessage(SSH_MSG_KEXINIT_Server)
	fmt.Printf("SSH_MSG_KEXINIT_Server: %v\n", SSH_MSG_KEXINIT_Server)
	fmt.Printf("SSH_MSG_KEXINIT_Server: %s\n", SSH_MSG_KEXINIT_Server)

	conn.Write(SSH_MSG_KEXINIT_Server)

	// Read client response
	response := make([]byte, 4096)
	n, err = conn.Read(response)
	if err != nil {
		log.Printf("Error reading client response: %v", err)
		return
	}

	handleSSHSession(conn)
	log.Println("=== SSH Connection Closed ===")
}
