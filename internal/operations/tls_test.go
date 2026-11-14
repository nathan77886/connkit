package operations

import "encoding/pem"

func certificatePEM(raw []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}
