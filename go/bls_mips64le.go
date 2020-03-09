// +build linux,mips64le

package bls

/*
#cgo LDFLAGS: -L../target/mips64el-unknown-linux-gnu/release -lbls_crypto -lbls_snark -ldl -lm
*/
import "C"
