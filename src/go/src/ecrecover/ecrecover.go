package main

import (
	"C"
	//"fmt"
	"crypto_csp"
	"encoding/hex"
	_ "unsafe"
)

//export RecoverAddress
func RecoverAddress(hashHex *C.char, signRhex, signShex *C.char, signV byte) (*C.char, *C.char) {
	hash, _ := hex.DecodeString( C.GoString(hashHex) )

	var signHex = C.GoString(signRhex) + C.GoString(signShex)
	sign, _ := hex.DecodeString(signHex)

	pub, err := crypto_csp.Ecrecover(hash, append(sign, signV))

	addr := crypto_csp.PubkeyBytesToAddress(pub)

	addrHex := hex.EncodeToString(addr)
	
	if err != nil {
		return nil, C.CString(err.Error())
	}
	
	return C.CString(addrHex), nil
}

func main() {}