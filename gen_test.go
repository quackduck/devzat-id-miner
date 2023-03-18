package main

import (
	"math/big"
	"testing"
)

// write a benchmark for generating cryptographically random slices of length 32 bytes
func BenchmarkRand32(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getRandBytes32()
	}
}

// write a benchmark that increments a big.Int
func BenchmarkBigInt(b *testing.B) {
	j := bytesToBigint(getRandBytes32())
	s := make([]byte, 32)
	oneAsBigint := big.NewInt(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j.Add(j, oneAsBigint)
		j.FillBytes(s)
	}
}
