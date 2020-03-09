// +build !android

package bls

/*
#cgo LDFLAGS: -L../target/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
