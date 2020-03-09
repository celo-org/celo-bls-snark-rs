// +build linux,arm64

package bls

/*
#cgo LDFLAGS: -L../target/aarch64-unknown-linux-gnu/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
