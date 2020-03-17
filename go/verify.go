package snark


/*
#cgo LDFLAGS: -L../target/release -lepoch_snark
#include "verify.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

var VerificationError = errors.New("SNARK proof verification failed")

/// Serialized Groth16 Proof
type Proof []byte

/// Serialized Verifying Key
type VerifyingKey []byte

/// The EpochBlock to be used for Verification in the SNARK
type EpochBlock struct {
	// Index of the epoch
	Index uint16
	/// Max non signers per block
	MaxNonSigners uint32
	/// Serialized public keys of the validators in this epoch
	PublicKeys []byte
}

func sliceToPtr(slice []byte) (*C.uchar, C.int) {
	if len(slice) == 0 {
		return nil, 0
	} else {
		return (*C.uchar)(unsafe.Pointer(&slice[0])), C.int(len(slice))
	}
}

func VerifyEpochs(
	verifyingKey VerifyingKey,
	proof Proof,
	firstEpoch EpochBlock,
	lastEpoch EpochBlock,
) error {
	vkPtr, vkLen := sliceToPtr(verifyingKey)
	proofPtr, proofLen := sliceToPtr(verifyingKey)

	publicKeysPtr, _ := sliceToPtr(firstEpoch.PublicKeys)
	firstEpoch := C.EpochBlockFFI {
		index: firstEpoch.Index,
		maximum_non_signers: firstEpoch.MaxNonSigners,
		pubkeys_num: len(firstEpoch.PublicKeys),
		pubkeys: publicKeysPtr,
	}

	publicKeysPtr, _ := sliceToPtr(lastEpoch.PublicKeys)
	lastEpoch := C.EpochBlockFFI {
		index: lastEpoch.Index,
		maximum_non_signers: lastEpoch.MaxNonSigners,
		pubkeys_num: len(lastEpoch.PublicKeys),
		pubkeys: publicKeysPtr,
	}

	success := C.verify(
		vkPtr,
		vkLen,
		proofPtr,
		proofLen,
		firstEpoch,
		lastEpoch,
	)

	if !success {
		return VerificationError
	}

	return nil
}