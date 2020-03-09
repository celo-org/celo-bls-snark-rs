// +build linux,mips64

package bls

/*
#cgo LDFLAGS: -L../target/mips64-unknown-linux-gnu/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
