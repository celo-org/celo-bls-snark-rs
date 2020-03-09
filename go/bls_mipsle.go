// +build linux,mipsle

package bls

/*
#cgo LDFLAGS: -L../target/mipsel-unknown-linux-gnu/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
