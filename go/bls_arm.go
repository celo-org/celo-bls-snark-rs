// +build linux,arm,!arm7

package bls

/*
#cgo LDFLAGS: -L../target/arm-unknown-linux-gnueabi/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
