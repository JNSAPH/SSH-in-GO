package constants

const (
	IDStringBanner = "SSH-2.0-Go-SSH-Server-1.0"
)

var SUPPORTED_KEX_ALGORITHMS = []string{
	"diffie-hellman-group14-sha1",
	"diffie-hellman-group-exchange-sha256",
}

var SUPPORTED_SERVER_HOST_KEY_ALGORITHMS = []string{
	"rsa-sha2-512",
}

var SUPPORTED_CLIENT_TO_SERVER_ENCRYPTION_ALGORITHMS = []string{
	"aes256-gcm@openssh.com",
}

var SUPPORTED_SERVER_TO_CLIENT_ENCRYPTION_ALGORITHMS = []string{
	"aes256-gcm@openssh.com",
}

var SUPPORTED_CLIENT_TO_SERVER_MAC_ALGORITHMS = []string{
	"hmac-sha1",
}

var SUPPORTED_SERVER_TO_CLIENT_MAC_ALGORITHMS = []string{
	"hmac-sha1",
}

var SUPPORTED_CLIENT_TO_SERVER_COMPRESSION_ALGORITHMS = []string{
	"none",
}

var SUPPORTED_SERVER_TO_CLIENT_COMPRESSION_ALGORITHMS = []string{
	"none",
}
