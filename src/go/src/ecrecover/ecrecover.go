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

//export SetNodeContainer
func SetNodeContainer(keyContainer, passphrase *C.char) (*C.char, *C.char) {
	crypto_csp.SetNodeContainer( C.GoString(keyContainer), C.GoString(passphrase) )

	return C.CString("ok"), nil
}

//export Sign
func Sign(container, pin, hashHex *C.char) (*C.char, *C.char) {
	hash, _ := hex.DecodeString( C.GoString(hashHex) )

	sign, err := crypto_csp.Sign( C.GoString(container), C.GoString(pin), hash)

	if err != nil {
		return nil, C.CString(err.Error())
	}

	signHex := hex.EncodeToString(sign)
	return C.CString(signHex), nil
}

func main() {}