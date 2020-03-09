// +build darwin,386

package bls

/*
#cgo LDFLAGS: -L../target/i686-apple-darwin/release -L../target/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
