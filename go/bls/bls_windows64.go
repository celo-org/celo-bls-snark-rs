// +build windows,amd64

package bls

/*
#cgo LDFLAGS: -L${SRCDIR}/../libs/x86_64-pc-windows-gnu -lepoch_snark -lm -lws2_32 -luserenv -lunwind
*/
import "C"

