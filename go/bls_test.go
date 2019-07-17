package bls

import (
	"testing"
)

func TestAggregatedSig(t *testing.T) {
	InitBLSCrypto()
	privateKey, _ := GeneratePrivateKey()
	defer privateKey.Destroy()
	publicKey, _ := privateKey.ToPublic()
	message := []byte("test")
	extraData := []byte("extra")
	signature, _ := privateKey.SignMessage(message, extraData, true)
	err := publicKey.VerifySignature(message, extraData, signature, true)
	if err != nil {
		t.Fatalf("failed verifying signature for pk 1, error was: %s", err)
	}

	privateKey2, _ := GeneratePrivateKey()
	defer privateKey2.Destroy()
	publicKey2, _ := privateKey2.ToPublic()
	signature2, _ := privateKey2.SignMessage(message, extraData, true)
	err = publicKey2.VerifySignature(message, extraData, signature2, true)
	if err != nil {
		t.Fatalf("failed verifying signature for pk 2, error was: %s", err)
	}

	aggergatedPublicKey, _ := AggregatePublicKeys([]*PublicKey{publicKey, publicKey2})
	aggergatedSignature, _ := AggregateSignatures([]*Signature{signature, signature2})
	err = aggergatedPublicKey.VerifySignature(message, extraData, aggergatedSignature, true)
	if err != nil {
		t.Fatalf("failed verifying signature for aggregated pk, error was: %s", err)
	}
	err = publicKey.VerifySignature(message, extraData, aggergatedSignature, true)
	if err == nil {
		t.Fatalf("succeeded verifying signature for wrong pk, shouldn't have!")
	}

	subtractedPublicKey, _ := AggregatePublicKeysSubtract(aggergatedPublicKey, []*PublicKey{publicKey2})
	err = subtractedPublicKey.VerifySignature(message, extraData, signature, true)
	if err != nil {
		t.Fatalf("failed verifying signature for subtractedPublicKey pk, error was: %s", err)
	}
}

func TestProofOfPossession(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	defer privateKey.Destroy()
	publicKey, _ := privateKey.ToPublic()
	signature, _ := privateKey.SignPoP()
	err := publicKey.VerifyPoP(signature)
	if err != nil {
		t.Fatalf("failed verifying PoP for pk 1, error was: %s", err)
	}

	privateKey2, _ := GeneratePrivateKey()
	defer privateKey2.Destroy()
	publicKey2, _ := privateKey2.ToPublic()
	if err != nil {
		t.Fatalf("failed verifying PoP for pk 2, error was: %s", err)
	}

	err = publicKey2.VerifyPoP(signature)
	if err == nil {
		t.Fatalf("succeeded verifying PoP for wrong pk, shouldn't have!")
	}
}

func TestNonCompositeSig(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	defer privateKey.Destroy()
	publicKey, _ := privateKey.ToPublic()
	message := []byte("test")
	extraData := []byte("extra")
	signature, _ := privateKey.SignMessage(message, extraData, false)
	err := publicKey.VerifySignature(message, extraData, signature, false)
	if err != nil {
		t.Fatalf("failed verifying signature for pk 1, error was: %s", err)
	}

	privateKey2, _ := GeneratePrivateKey()
	defer privateKey2.Destroy()
	publicKey2, _ := privateKey2.ToPublic()
	signature2, _ := privateKey2.SignMessage(message, extraData, false)
	err = publicKey2.VerifySignature(message, extraData, signature2, false)
	if err != nil {
		t.Fatalf("failed verifying signature for pk 2, error was: %s", err)
	}

	aggergatedPublicKey, _ := AggregatePublicKeys([]*PublicKey{publicKey, publicKey2})
	aggergatedSignature, _ := AggregateSignatures([]*Signature{signature, signature2})
	err = aggergatedPublicKey.VerifySignature(message, extraData, aggergatedSignature, false)
	if err != nil {
		t.Fatalf("failed verifying signature for aggregated pk, error was: %s", err)
	}
	err = publicKey.VerifySignature(message, extraData, aggergatedSignature, false)
	if err == nil {
		t.Fatalf("succeeded verifying signature for wrong pk, shouldn't have!")
	}

}
