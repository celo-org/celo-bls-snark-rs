package bls

// +build !linux,!darwin,android
// +build arm

/*
#cgo LDFLAGS: -L../bls/target/armv7-linux-androideabi/release -lbls_zexe -ldl -lm
*/
import "C"
