package bls

// +build linux,darwin,!android

/*
#cgo LDFLAGS: -L../bls/target/release -lbls_zexe -ldl -lm
*/
import "C"
