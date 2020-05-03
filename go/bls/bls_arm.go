// +build linux,arm,!arm7

package bls

/*
#cgo LDFLAGS: -L${SRCDIR}/../libs/arm-unknown-linux-gnueabi -lepoch_snark -ldl -lm
*/
import "C"
