package handlers

import (
	"crypto/rsa"
	"log"
	"net"

	"jnsaph/constants"
	"jnsaph/keyExchange"
	"jnsaph/utils"
)

// HandleSSHConnection manages the SSH connection process.
// For more details, see RFC 4253: https://tools.ietf.org/html/rfc4253
func HandleSSHConnection(conn net.Conn, privateKey *rsa.PrivateKey) {
	log.Println("=== SSH Connection ===")
	log.Printf("SSH connection established from %s", conn.RemoteAddr())

	// ID-String exchange Client -> Server
	idString := make([]byte, 1024)
	n, err := conn.Read(idString)
	if err != nil {
		log.Printf("Error reading ID-String: %v", err)
		return
	}
	log.Printf("ID-String from Client: %s", idString[:n])

	// ID-String exchange Server -> Client
	banner := constants.IDStringBanner
	if _, err := conn.Write([]byte(banner + "\r\n")); err != nil {
		log.Printf("Error sending banner: %v", err)
		return
	}

	// SSH_MSG_KEXINIT Client -> Server
	keyExchangeMsg := make([]byte, 4096)
	n, err = conn.Read(keyExchangeMsg)
	if err != nil {
		log.Printf("Error reading Key Exchange Message: %v", err)
		return
	}

	PARSED_KEY_EXCHANGE_MSG := utils.ParseMessagePackage(keyExchangeMsg[:n])
	SSH_MSG_KEXINIT_Client := keyExchange.ParseSSHMsgKexinit([]byte(string(PARSED_KEY_EXCHANGE_MSG.Payload) + string(PARSED_KEY_EXCHANGE_MSG.RandomPadding) + string(PARSED_KEY_EXCHANGE_MSG.MAC))) // This is stupid

	// SSH_MSG_KEXINIT Server -> Client
	SSH_MSG_KEXINIT_Server, err := keyExchange.CreateSSHMsgKexinit(SSH_MSG_KEXINIT_Client)
	if err != nil {
		log.Fatalf("Error creating SSH_MSG_KEXINIT: %v", err)
	}

	SSH_MSG_KEXINIT_Server = utils.CreateSSHMessage(SSH_MSG_KEXINIT_Server)
	if _, err := conn.Write(SSH_MSG_KEXINIT_Server); err != nil {
		log.Printf("Error sending SSH_MSG_KEXINIT: %v", err)
		return
	}

	// KEY EXCHANGE
	// Docs: RFC 4253, Section 7.1 and 7.2
	response := make([]byte, 4096)
	n, err = conn.Read(response)
	if err != nil {
		log.Printf("Error reading client response: %v", err)
		return
	}

	otasdf := utils.ParseMessagePackage(response[:n])
	log.Printf("Client response: %v", otasdf)

	handleSSHSession(conn)
	log.Println("=== SSH Connection Closed ===")
}
