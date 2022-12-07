package scrypt_test

import (
	"fmt"
	"testing"

	"github.com/matryer/is"

	"github.com/sour-is/go-passwd"
	"github.com/sour-is/go-passwd/pkg/scrypt"
)

func TestPasswdHash(t *testing.T) {
	type testCase struct {
		pass, hash string
	}

	tests := []testCase{}
	algos := scrypt.All

	is := is.New(t)
	// Generate additional test cases for each algo.
	for _, algo := range algos {
		hash, err := algo.Passwd("passwd", "")
		is.NoErr(err)
		tests = append(tests, testCase{"passwd", hash})
	}

	pass := passwd.New(algos...)

	for i, tt := range tests {
		t.Run(fmt.Sprint("Test-", i), func(t *testing.T) {
			is := is.New(t)

			hash, err := pass.Passwd(tt.pass, tt.hash)
			is.NoErr(err)
			is.Equal(hash, tt.hash)
		})
	}
}
