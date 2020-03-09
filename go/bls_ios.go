// +build ios

package bls

/*
#cgo LDFLAGS: -L../target/universal/release -lbls_crypto -lbls_snark -ldl -lm -framework Security -framework Foundation
*/
import "C"
