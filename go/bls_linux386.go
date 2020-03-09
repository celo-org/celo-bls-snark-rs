// +build linux,386

package bls

/*
#cgo LDFLAGS: -L../target/i686-unknown-linux-gnu/release -lbls_zexe -lbls_snark -ldl -lm
*/
import "C"
