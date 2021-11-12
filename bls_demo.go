package main

import (
	"fmt"

	"github.com/prysmaticlabs/prysm/crypto/bls/blst"
	"github.com/prysmaticlabs/prysm/crypto/bls/common"

	"github.com/prysmaticlabs/prysm/crypto/bls/herumi"
)

var (
	prvKey1 common.SecretKey
	pubKey1 common.PublicKey
	prvKey2 common.SecretKey
	pubKey2 common.PublicKey
	prvKey3 common.SecretKey
	pubKey3 common.PublicKey

	msg = [32]byte{101, 131, 24, 49, 81, 116, 222, 176, 189, 214, 82, 243, 72, 211, 168, 55, 209, 120, 224, 169, 149, 225, 192, 152, 168, 139, 121, 136, 18, 111, 159, 71}
)

func init() {
	herumi.HerumiInit()
}

func GenerateKey() {
	var err error
	prvKey1, err = blst.RandKey()
	if err != nil {
		fmt.Errorf("Can't generate bls private key\n")
	}
	pubKey1 = prvKey1.PublicKey()
	fmt.Printf("[Account1]\nprivate key: %v\npublic key: %v\n\n", prvKey1.Marshal(), pubKey1.Marshal())

	prvKey2, err = blst.RandKey()
	if err != nil {
		fmt.Errorf("Can't generate bls private key\n")
	}
	pubKey2 = prvKey2.PublicKey()
	fmt.Printf("[Account2]\nprivate key: %v\npublic key: %v\n\n", prvKey2.Marshal(), pubKey2.Marshal())

	prvKey3, err = blst.RandKey()
	if err != nil {
		fmt.Errorf("Can't generate bls private key\n")
	}
	pubKey3 = prvKey3.PublicKey()
	fmt.Printf("[Account3]\nprivate key: %v\npublic key: %v\n\n", prvKey3.Marshal(), pubKey3.Marshal())
}

func SingleSignAndVerify() {
	fmt.Printf("============================================\n")
	fmt.Printf("=========Single sign and verify ============\n")

	sig1 := prvKey1.Sign(msg[:])
	fmt.Printf("Account1 signature: %v\n", sig1.Marshal())
	sig2 := prvKey2.Sign(msg[:])
	fmt.Printf("Account2 signature: %v\n", sig2.Marshal())
	sig3 := prvKey3.Sign(msg[:])
	fmt.Printf("Account3 signature: %v\n", sig3.Marshal())

	if !sig1.Verify(pubKey1, msg[:]) {
		fmt.Printf("Verify account1 signature failed\n")
	}
	if !sig2.Verify(pubKey2, msg[:]) {
		fmt.Printf("Verify account2 signature failed\n")
	}
	if !sig3.Verify(pubKey3, msg[:]) {
		fmt.Printf("Verify account3 signature failed\n")
	}
	if sig1.Verify(pubKey2, msg[:]) {
		fmt.Printf("Verify account1 signature by account2 success, rediculous\n")
	}

	fmt.Printf("============================================\n")
}

func AggregateSignAndVerify() {
	fmt.Printf("============================================\n")
	fmt.Printf("=======Aggregate sign and verify ===========\n")

	sig1 := prvKey1.Sign(msg[:])
	fmt.Printf("Account1 signature: %v\n", sig1.Marshal())
	sig2 := prvKey2.Sign(msg[:])
	fmt.Printf("Account2 signature: %v\n", sig2.Marshal())
	sig3 := prvKey3.Sign(msg[:])
	fmt.Printf("Account3 signature: %v\n", sig3.Marshal())

	var sigs = [3]common.Signature{sig1, sig2, sig3}
	var pubKeys = [3]common.PublicKey{pubKey1, pubKey2, pubKey3}

	sig := blst.AggregateSignatures(sigs[:])
	fmt.Printf("Aggregated signature: %v\n", sig.Marshal())
	if !sig.FastAggregateVerify(pubKeys[:], msg) {
		fmt.Printf("Fast aggregate verify signature failed\n")
	}

	fmt.Printf("============================================\n")
}

func AggregatePubkeyVerifySignature() {
	fmt.Printf("============================================\n")
	fmt.Printf("====Aggregate pubkey and verify signature =======\n")

	sig1 := prvKey1.Sign(msg[:])
	fmt.Printf("Account1 signature: %v\n", sig1.Marshal())
	sig2 := prvKey2.Sign(msg[:])
	fmt.Printf("Account2 signature: %v\n", sig2.Marshal())
	sig3 := prvKey3.Sign(msg[:])
	fmt.Printf("Account3 signature: %v\n", sig3.Marshal())

	var sigs = [3]common.Signature{sig1, sig2, sig3}

	sig := blst.AggregateSignatures(sigs[:])
	fmt.Printf("Aggregated signature: %v\n", sig.Marshal())

	pubkey := pubKey1.Aggregate(pubKey2).Aggregate(pubKey3)
	fmt.Printf("Aggregated pubkey: %v\n", pubkey.Marshal())
	if !sig.Verify(pubkey, msg[:]) {
		//if !sig.Verify(pubkey, []byte("hello world")) {
		fmt.Printf("Aggregated pubkey verify aggregate signature failed\n")
	}

	fmt.Printf("============================================\n")
}

func main() {
	GenerateKey()
	SingleSignAndVerify()
	AggregateSignAndVerify()
	AggregatePubkeyVerifySignature()
}
