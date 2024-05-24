package keyExchange

import (
	"fmt"
	t "jnsaph/types"
	"log"
)

type SSHMsgKexdhPacket struct {
	SSH_MSG_KEXDH byte
	e             t.MPINT
}

func ParseSSHMsgKexdh(packet []byte) SSHMsgKexdhPacket {
	SSH_MSG_KEXDH := packet[0]

	// Check if SSH_MSG_KEXDH is within the valid range
	if SSH_MSG_KEXDH < 30 || SSH_MSG_KEXDH > 49 {
		log.Fatalf("Invalid SSH_MSG_KEXDH: %v", SSH_MSG_KEXDH)
	}

	data := packet[1:]

	parsed_data := t.ParseMPInt(data)
	fmt.Print(parsed_data)

	return SSHMsgKexdhPacket{
		SSH_MSG_KEXDH: SSH_MSG_KEXDH,
		e:             parsed_data,
	}
}

/*
The server then responds with the following:

	byte      SSH_MSG_KEXDH_REPLY
	string    server public host key and certificates (K_S)
	mpint     f
	string    signature of H
*/
func CreateSSHMsgKexdhPacket(e SSHMsgKexdhPacket) []byte {
	SSH_MSG_KEXDH_REPLY := byte(31)

	// Todo: Implement this
	panic("Not implemented")

	packet := []byte{SSH_MSG_KEXDH_REPLY}

	return packet
}
