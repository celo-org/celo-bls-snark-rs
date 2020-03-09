// +build linux,mips

package bls

/*
#cgo LDFLAGS: -L../target/mips-unknown-linux-gnu/release -lbls_zexe -lbls_snark -ldl -lm
*/
import "C"
