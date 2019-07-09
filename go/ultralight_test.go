package ultralight

import (
	"testing"
)

func TestAggregatedSig(t *testing.T) {
	InitBLSCrypto()
	privateKey, _ := GeneratePrivateKey()
	defer privateKey.Destroy()
	publicKey, _ := privateKey.ToPublic()
	message := []byte("test")
	signature, _ := privateKey.SignMessage(message)
	err := publicKey.VerifySignature(message, signature)
	if err != nil {
		t.Fatalf("failed verifying signature for pk 1, error was: %s", err)
	}

	privateKey2, _ := GeneratePrivateKey()
	defer privateKey2.Destroy()
	publicKey2, _ := privateKey2.ToPublic()
	signature2, _ := privateKey2.SignMessage(message)
	err = publicKey2.VerifySignature(message, signature2)
	if err != nil {
		t.Fatalf("failed verifying signature for pk 2, error was: %s", err)
	}

	aggergatedPublicKey, _ := AggregatePublicKeys([]*PublicKey{publicKey, publicKey2})
	aggergatedSignature, _ := AggregateSignatures([]*Signature{signature, signature2})
	err = aggergatedPublicKey.VerifySignature(message, aggergatedSignature)
	if err != nil {
		t.Fatalf("failed verifying signature for aggregated pk, error was: %s", err)
	}
	err = publicKey.VerifySignature(message, aggergatedSignature)
	if err == nil {
		t.Fatalf("succeed verifying signature for wrong pk, shouldn't have!")
	}

}
