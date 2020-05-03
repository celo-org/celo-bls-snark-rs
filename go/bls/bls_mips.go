// +build linux,mips

package bls

/*
#cgo LDFLAGS: -L${SRCDIR}/../libs/mips-unknown-linux-gnu -lepoch_snark -ldl -lm
*/
import "C"
