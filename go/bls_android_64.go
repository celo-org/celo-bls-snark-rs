package bls

// +build !linux,!darwin,android
// +build arm64

/*
#cgo LDFLAGS: -L../bls/target/aarch64-linux-android/release -lbls_zexe -ldl -lm
*/
import "C"
