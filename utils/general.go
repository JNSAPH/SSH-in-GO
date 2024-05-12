package utils

func SeperateHexPairs(hexString string) []string {
	var hexPairs []string
	for i := 0; i < len(hexString); i += 2 {
		hexPairs = append(hexPairs, hexString[i:i+2])
	}
	return hexPairs
}
