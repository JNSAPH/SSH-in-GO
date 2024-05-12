package main

import (
	"crypto/rand"
	"crypto/rsa"
	"jnsaph/handlers"
	"log"
	"net"
)

func main() {
	const hostname string = "localhost"
	const port string = "2222"

	// Generate RSA key pair for the server
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Start SSH server
	listener, err := net.Listen("tcp", hostname+":"+port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("SSH server listening on %s:%s", hostname, port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept incoming connection: %v", err)
		}
		go handlers.HandleSSHConnection(conn, privateKey)
	}
}
