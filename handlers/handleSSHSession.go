package handlers

import (
	"log"
	"net"
)

// responsible for handling the SSH session after the handshake
func handleSSHSession(conn net.Conn) {
	log.Printf("SSH connection established with %s", conn.RemoteAddr())

	// Close connection after sending response
	log.Println("Closing SSH session...")
	conn.Close()
}
