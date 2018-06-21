package crypto_csp

import (
	"errors"
	"math/big"
	"fmt"
//	"github.com/fastchain/geth-gost/common"
//	"github.com/fastchain/geth-gost/rlp"
//	"github.com/fastchain/geth-gost/sha3"
//	"os"
//	"io"
// 	"io/ioutil"
	_ "encoding/hex"
	//"encoding/binary"
)


var(
	nodeContainer = ""
	nodePin = ""
)

func SetNodeContainer(keyContainer, passphrase string) {
	nodeContainer = keyContainer
	nodePin = passphrase
}
/*
func GetUncertifiedHash(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}*/
/*
func GetUncertifiedHashAsHash(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}
*/
func Gost34112012_256(data ...[]byte) []byte {
	var d []byte
	for _, b := range data {
		d = append(d, b...)
	}
	return cspHash(d)
}
/*
func Gost34112012_256Hash(data ...[]byte) (h common.Hash) {
	var d []byte
	for _, b := range data {
		d = append(d, b...)
	}
	h = common.BytesToHash(cspHash(d))
	return h
}*/
/*
// LoadContainerInfo loads a CSP key container name from the given file.
func LoadContainerInfo(file string) (string, error) {
	buf := make([]byte, 140)
	fd, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return "", err
	}

	key := string(buf)
	if err != nil {
		return "", err
	}

	return key, nil
}

// SaveContainerInfo saves a CSP key container name to the given file with
// restrictive permissions.
func SaveContainerInfo(file string, key string) error {
	return ioutil.WriteFile(file, []byte(key), 0600)
}

func CreateNewKeysContainer(passphrase string) string {
	return cspCreateContainer(passphrase)
}

func DeleteKeysContainer(container, passphrase string) {
	cspDeleteContainer(container, passphrase)
}

func UpdateKeysContainerPin(container, passphrase, newPassphrase string) {
	cspUpdateContainerPin(container, passphrase, newPassphrase)
}

func GetPublicKey(container, pin string) []byte {
	return cspGetPurePublicKey(container, pin)
}
*//*
func PublicKeyBytes(pub *PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return pub.Raw()
}*/

func Sign(container, pin string, hash []byte) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	curve, _ := NewCurveFromParams256(CurveParamsGostR34102001CryptoProA)
	sig, err = signCompact(curve, container, pin, hash)
	return
}

func Ecrecover(hash, sig []byte) ([]byte, error) {
	curve, _ := NewCurveFromParams256(CurveParamsGostR34102001CryptoProA)
	pub, err := recoverCompact(curve, hash, sig)
	if err != nil {
		fmt.Printf("Ecrecover error: %s\n", err)
		return nil, err
	}

	return pub.Raw(), nil
}
/*
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	vint := uint32(v)
	//// reject upper range of s values (ECDSA malleability)
	//// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	//if homestead && s.Cmp(secp256k1.HalfN) > 0 {
	//	return false
	//}
	curve, _ := NewCurveFromParams256(CurveParamsGostR34102001CryptoProA)
	// Frontier: allow s to be in full N range
	if s.Cmp(curve.Q) >= 0 {
		return false
	}
	if r.Cmp(curve.Q) < 0 && (vint == 27 || vint == 28) {
		return true
	} else {
		return false
	}
}*/
/*
func SigToPub(hash, sig []byte) (*PublicKey, error) {
	curve, _ := NewCurveFromParams256(CurveParamsGostR34102001CryptoProA)
	pub, err := recoverCompact(curve, hash, sig)
	if err != nil {
		return nil, err
	}

	return pub, nil
}*/

func PubkeyBytesToAddress(p []byte) []byte {
	hashAddr :=  Gost34112012_256(p)
	return hashAddr[12:]
}
/*
func (tlsProtocol *Tls) InitTLS(container, passphrase string) (error) {
	return tlsProtocol.cspInitialiseTLS(container, passphrase)
}

func (tlsProtocol *Tls) TlsServerHello(packetIn []byte) (*ConnectionContext, []byte, uint32) {
	return tlsProtocol.cspTlsServerHello(packetIn)
}

func (tlsProtocol *Tls) TlsClientHello(node []byte) (*ConnectionContext, []byte, uint32) {
	return tlsProtocol.cspTlsClientHello(node)
}*/
/*
func (context *ConnectionContext) TlsServerStep(packet []byte) ([]byte, uint32) {
	return context.cspTlsServerStep(packet)
}

func (context *ConnectionContext) TlsClientStep(packet []byte) ([]byte, uint32) {
	return context.cspTlsClientStep(packet)
}

func (context *ConnectionContext) TlsEncrypt(packet []byte) ([]byte, uint32) {
	return context.cspTlsEncrypt(packet)
}

func (context *ConnectionContext) TlsDecrypt(packet []byte) ([]byte, uint32) {
	return context.cspTlsDecrypt(packet)
}

func (context *ConnectionContext) TlsDisconnect() {
	context.cspDisconnect()
}

func (context *ConnectionContext) GetHeaderTrailerSize() uint64 {
	return context.headerSize + context.trailerSize
}

func (context *ConnectionContext) GetMsgMaxSize() uint64 {
	return context.msgSize
}

func (context *ConnectionContext) TlsGetSubjectName() []byte {
	return context.cspTlsGetSubjectName()
}*/
/*
// Creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Gost34112012_256(data)[12:])
}*/

func signCompact(curve *Curve, container, pin string, hash []byte) ([]byte, error) {
	revHash := make([]byte, 32)
	copy(revHash, hash)
	reverse(revHash)

	signature := cspSignHash(container, pin, revHash)
	pub, _ := NewPublicKey(curve, cspGetPurePublicKey(container, pin))

	sig := make([]byte, 64)
	copy(sig, signature)
	reverse(sig)
	s := bytes2big(sig[:32])
	r := bytes2big(sig[32:])

	for i := 0; i < (1+1)*2; i++ {
		pk, err := recoverKeyFromSignature(curve, r, s, hash, i)
		if err == nil && pk.X.Cmp(pub.X) == 0 && pk.Y.Cmp(pub.Y) == 0 {
			result := make([]byte, 0, 2*32+1)
			result = append(result, sig[32:]...)
			result = append(result, sig[:32]...)
			result = append(result, byte(i))
			return result, nil
		}
	}

	return nil, errors.New("no valid solution for pubkey found")
}

func recoverCompact(curve *Curve, hash, signature []byte) (*PublicKey, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, errors.New("invalid compact signature size")
	}

	iteration := int(signature[64] - 27) //int((signature[64]) & ^byte(4))

	// format is <bitlen R><bitlen S><header byte>
	r := bytes2big(signature[:32])
	s := bytes2big(signature[32:64])

	// The iteration used here was encoded
	key, err := recoverKeyFromSignature(curve, r, s, hash, iteration)
	if err != nil {
		return nil, err
	}

	verified := cspVerifySignature(hash, signature, key.Raw())
	if !verified {
		return nil, errors.New("Restored pubkey doesn't verify given signature using CSP")
	}

	return key, nil
}

func recoverKeyFromSignature(curve *Curve, r, s *big.Int, msg []byte, iter int) (*PublicKey, error) {
	// x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Q,
		new(big.Int).SetInt64(int64(iter/2)))
	
	Rx.Add(Rx, r)
	if Rx.Cmp(curve.P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// Convert Rx to point R. If we are on an odd
	// iteration then will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := curve.DecompressPoint(Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// Check n*R is point at infinity
	nRx, nRy, _ := curve.ScalarMult(Rx, Ry, curve.Q.Bytes())
	if nRx.Sign() != 0 || nRy.Sign() != 0 {
		return nil, errors.New("n*R does not equal the point at infinity")
	}

	// Converting bytes of message hash to int.
	e := bytes2big(msg)

	// We calculate the two terms sG and eR separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sG-eR)
	invr := new(big.Int).ModInverse(r, curve.Q)

	// first term.
	invrS := new(big.Int).Mul(invr, s)
	invrS.Mod(invrS, curve.Q)
	sGx, sGy, _ := curve.ScalarBaseMult(invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Q)
	e.Mul(e, invr)
	e.Mod(e, curve.Q)
	minuseRx, minuseRy, err := curve.ScalarMult(Rx, Ry, e.Bytes())
	Qx, Qy := curve.Add(sGx, sGy, minuseRx, minuseRy)

	return &PublicKey{
		Curve: curve,
		Ds:    32,
		X:     Qx,
		Y:     Qy,
	}, nil
}