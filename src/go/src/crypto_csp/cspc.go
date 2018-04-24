package crypto_csp

/*
#cgo linux CFLAGS: -I/opt/cprocsp/include/cpcsp/
#cgo linux,386 darwin CFLAGS: -I/opt/cprocsp/include/cpcsp/
#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/cpcsp/
#cgo 386 darwin LDFLAGS: -L/opt/cprocsp/lib/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lrdrsup -lssp -lcpext -lurlretrieve -lcpasn1 -lcplib -lcpalloc  -ljemalloc
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo windows LDFLAGS: -lcrypt32 -lpthread

#include "csp.c"
*/
import "C"
import (
	"unsafe"
	_ "encoding/hex"
	_ "encoding/binary"
	_ "fmt"
)
/*
type credentials struct {
	credHandle C.CredHandle
}

type Tls struct {
	sspi			C.PSecurityFunctionTable
	serverCredentials	C.CredHandle
	clientCredentials	C.CredHandle
}

type tlsPacket struct {
	packet 				C.tlsPacket_t
}

func (packet tlsPacket) getPacket() []byte {
	cPacketSize := uintCToInt(packet.packet.outPacketSize)
	b := []byte(C.GoStringN(packet.packet.outPacket, cPacketSize))

	return b
}

func (packet tlsPacket) getStatus() uint32 {
	b := uint32(packet.packet.status)

	return b
}

func (packet tlsPacket) getStatusString() string {
	s := packet.getStatus()
	return GetStatusString(s)
}

func GetStatusString(status uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, status)
	st := "0x" + hex.EncodeToString(b)

	return st
}

type ConnectionContext struct {
	tlsProtocol 			*Tls

	context    			C.CtxtHandle
	headerSize			uint64
	trailerSize			uint64
	msgSize				uint64
}

func (context *ConnectionContext) printCtxt() string {
	return fmt.Sprintf("Tls context is: %v\n", context.context)
}
*/
func cspHash(s []byte) []byte {
	if len(s) == 0 {
		s = make([]byte, 0)
	}
	cs := bytePtrChar(s)
	ln := intToUintC(len(s))
	res := C.CalculateHash(cs, ln)
	data := (*C.char)(unsafe.Pointer(res))
	b := []byte(C.GoStringN(data, 32))

	return b
}

func bytePtrChar(s []byte) *C.char {
	if len(s) != 0 {
		return (*C.char)(unsafe.Pointer(&s[0]))
	}
	return nil
}

func intToUintC(n int) C.uint32_t {
	return *(*C.uint32_t)(unsafe.Pointer(&n))
}

/*

func cspSignHash(container, pin string, hash []byte) []byte {
	cHash := bytePtrUint8(hash)
	cContainer := C.CString(container)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))

	res := C.SignHash(cContainer, cPin, cHash)
	data := (*C.char)(unsafe.Pointer(res))
	b := []byte(C.GoStringN(data, 64))

	return b
}

func cspVerifySignature(container, pin string, hash, signature, pubkey []byte) bool {
	sig := make([]byte, 64)
	sig = append(sig, signature[32:64]...)
	sig = append(sig, signature[:32]...)
	reverse(sig)

	revHash := make([]byte, 32)
	copy(revHash, hash)
	reverse(revHash)

	cContainer := C.CString(container)
	cPin := C.CString(pin)
	cHash := bytePtrUint8(revHash)
	cSig := bytePtrUint8(sig)
	cPub := bytePtrUint8(pubkey)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))

	return uint8ToBool(C.SignatureVerify(cContainer, cPin, cHash, cSig, cPub))
}

func cspGetPurePublicKey(container, pin string) []byte {
	cContainer := C.CString(container)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))

	pub := C.GetPurePubKey(cContainer, cPin)
	data := (*C.char)(unsafe.Pointer(pub))
	b := []byte(C.GoStringN(data, 64))

	return b
}

func cspCreateContainer(pin string) string {
	tempContainer := "\\\\.\\HDIMAGE\\temp"
	tempPin := "temppin1234"
	cTempContainer := C.CString(tempContainer)
	cTempPin := C.CString(tempPin)

	defer C.free(unsafe.Pointer(cTempContainer))
	defer C.free(unsafe.Pointer(cTempPin))

	C.CreateTempContainer(cTempContainer, cTempPin)

	pub := C.GetPurePubKey(cTempContainer, cTempPin)
	data := (*C.char)(unsafe.Pointer(pub))
	b := []byte(C.GoStringN(data, 64))

	container := "\\\\.\\HDIMAGE\\" + hex.EncodeToString(b)
	cContainer := C.CString(container)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))

	C.CopySignKeyToNewContainer(cTempContainer, cTempPin, cContainer, cPin)
	C.DeleteContainer(cTempContainer)

	return container
}

func cspDeleteContainer(container, pin string) {
	cContainer := C.CString(container)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))

	C.DeleteContainerWithPin(cContainer, cPin)
}

func cspUpdateContainerPin(container, pin, newPin string) {
	cContainer := C.CString(container)
	cPin := C.CString(pin)
	cNewPin := C.CString(newPin)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))
	defer C.free(unsafe.Pointer(cNewPin))

	C.UpdateContainerPin(cContainer, cPin, cNewPin)
}

func (tlsProtocol *Tls) cspInitialiseTLS(container, pin string) (error) {
	cContainer := C.CString(container)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cContainer))
	defer C.free(unsafe.Pointer(cPin))

	tlsProtocol.sspi = C.LoadSecurityLibrary()
	if tlsProtocol.sspi == nil {
		return fmt.Errorf("Loading CSP SSPI library failed")
	}

	selfSignedCert := C.CreateSelfSignedCertificate(cContainer, cPin)

	sRes := C.CreateServerCredentials(tlsProtocol.sspi, selfSignedCert, &tlsProtocol.serverCredentials)
	cRes := C.CreateClientCredentials(tlsProtocol.sspi, selfSignedCert, &tlsProtocol.clientCredentials)

	if sRes != 0 || cRes != 0 {
		return fmt.Errorf("Creating credentials failed with error: %v (server), %v (client)", sRes, cRes)
	}

	return nil
}

func (tlsProtocol *Tls) cspTlsServerHello(packetIn []byte) (*ConnectionContext, []byte, uint32) {
	cPacket := bytePtrChar(packetIn)
	cPacketSize := intToUintC(len(packetIn))
	srvContext := &ConnectionContext{tlsProtocol: tlsProtocol}
	packetOut := &tlsPacket{}
	packetOut.packet = C.ServerHello(tlsProtocol.sspi, &tlsProtocol.serverCredentials, &srvContext.context, cPacket, cPacketSize)
	srvContext.headerSize, srvContext.trailerSize, srvContext.msgSize = srvContext.cspTlsGetSizeParameters()
	//fmt.Printf("Server hello: %v; %v", packetOut.getStatusString(), srvContext.printCtxt())

	return srvContext, packetOut.getPacket(), packetOut.getStatus()
}

func (tlsProtocol *Tls) cspTlsClientHello(node []byte) (*ConnectionContext, []byte, uint32) {
	cNode := bytePtrChar(node)
	clnContext := &ConnectionContext{tlsProtocol: tlsProtocol}
	packetOut := &tlsPacket{}
	packetOut.packet = C.ClientHello(tlsProtocol.sspi, &tlsProtocol.clientCredentials, cNode, &clnContext.context)
	clnContext.headerSize, clnContext.trailerSize, clnContext.msgSize = clnContext.cspTlsGetSizeParameters()
	//fmt.Printf("Client hello: %v; %v", packetOut.getStatusString(), clnContext.printCtxt())

	return clnContext, packetOut.getPacket(), packetOut.getStatus()
}

func (context *ConnectionContext) cspTlsServerStep(packet []byte) ([]byte, uint32) {
	cPacket := bytePtrChar(packet)
	cPacketSize := intToUintC(len(packet))
	packetOut := &tlsPacket{}
	packetOut.packet = C.ServerHandshakeStep(context.tlsProtocol.sspi, &context.tlsProtocol.serverCredentials, &context.context, cPacket, cPacketSize)
	//fmt.Printf("Server step: %v; %v", packetOut.getStatusString(), context.printCtxt())

	return packetOut.getPacket(), packetOut.getStatus()
}

func (context *ConnectionContext) cspTlsClientStep(packet []byte) ([]byte, uint32) {
	cPacket := bytePtrChar(packet)
	cPacketSize := intToUintC(len(packet))
	packetOut := &tlsPacket{}
	packetOut.packet = C.ClientHandshakeStep(context.tlsProtocol.sspi, &context.tlsProtocol.clientCredentials, &context.context, cPacket, cPacketSize)
	//fmt.Printf("Client step: %v; %v", packetOut.getStatusString(), context.printCtxt())

	return packetOut.getPacket(), packetOut.getStatus()
}

func (context *ConnectionContext) cspTlsEncrypt(packet []byte) ([]byte, uint32) {
	cPacket := bytePtrChar(packet)
	cPacketSize := intToUintC(len(packet))
	packetOut := &tlsPacket{}
	packetOut.packet = C.Encrypt(context.tlsProtocol.sspi, &context.context, cPacket, cPacketSize)
	//fmt.Printf("Encrypting: %v; %v", packetOut.getStatusString(), context.printCtxt())

	return packetOut.getPacket(), packetOut.getStatus()
}

func (context *ConnectionContext) cspTlsDecrypt(packet []byte) ([]byte, uint32) {
	cPacket := bytePtrChar(packet)
	cPacketSize := intToUintC(len(packet))
	packetOut := &tlsPacket{}
	packetOut.packet = C.Decrypt(context.tlsProtocol.sspi, &context.context, cPacket, cPacketSize)
	//fmt.Printf("Decrypting: %v; %v", packetOut.getStatusString(), context.printCtxt())

	return packetOut.getPacket(), packetOut.getStatus()
}

func (context *ConnectionContext) cspDisconnect() {
	C.Disconnect(context.tlsProtocol.sspi, &context.context)
}

func (context *ConnectionContext) cspTlsGetSizeParameters() (header, trailer, message uint64) {
	var sizes C.SecPkgContext_StreamSizes
	sizes = C.GetTlsSizeParameters(context.tlsProtocol.sspi, &context.context)
	header = ulongCToUint64(sizes.cbHeader)
	trailer = ulongCToUint64(sizes.cbTrailer)
	message = ulongCToUint64(sizes.cbMaximumMessage)

	return
}

func (context *ConnectionContext) cspTlsGetSubjectName() []byte {
	cSubjName := C.GetRemoteSubjectName(context.tlsProtocol.sspi, &context.context)
	data := (*C.char)(unsafe.Pointer(cSubjName))
	b, _ := hex.DecodeString(C.GoStringN(data, 128))

	return b
}

func intToUintC(n int) C.uint32_t {
	return *(*C.uint32_t)(unsafe.Pointer(&n))
}

func uintCToInt(n C.uint32_t) C.int {
	return (C.int)(n)
}

func ulongCToUint64(n C.ulong) uint64 {
	return uint64(n)
}

func bytePtrChar(s []byte) *C.char {
	if len(s) != 0 {
		return (*C.char)(unsafe.Pointer(&s[0]))
	}
	return nil
}

func bytePtrUint8(s []byte) *C.uint8_t {
	if len(s) != 0 {
		return (*C.uint8_t)(unsafe.Pointer(&s[0]))
	}
	return nil
}

func uint8ToBool(b C.uint8_t) bool {
	return b == 1
}
*/