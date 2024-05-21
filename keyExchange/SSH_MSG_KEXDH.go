package keyExchange

import (
	"jnsaph/utils"
	"log"
)

func ParseSSHMsgKexdh(packet []byte) []byte {
	SSH_MSG_KEXDH := packet[0]

	// Check if SSH_MSG_KEXDH is within the valid range
	if SSH_MSG_KEXDH < 30 || SSH_MSG_KEXDH > 49 {
		log.Fatalf("Invalid SSH_MSG_KEXDH: %v", SSH_MSG_KEXDH)
	}

	data := packet[1:]

	utils.ReadMpint(data)

	return data
}
