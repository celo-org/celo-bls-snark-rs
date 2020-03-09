// +build darwin,386

package bls

/*
#cgo LDFLAGS: -L../target/i686-apple-darwin/release -L../target/release -lbls_zexe -lbls_snark -ldl -lm
*/
import "C"
