package scrypt_test

import (
	"fmt"
	"testing"

	"github.com/matryer/is"

	"github.com/sour-is/go-passwd"
	"github.com/sour-is/go-passwd/pkg/scrypt"
	"github.com/sour-is/go-passwd/pkg/unix"
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

func TestPasswdIsPreferred(t *testing.T) {
	is := is.New(t)

	pass := passwd.New(scrypt.Scrypt2, &unix.MD5{})

	ok := pass.IsPreferred("16384$8$1$b97ed09792dd74b71dcb7fc8caf04a89$0b5cda82b17298ec4bf6d2139f7ea8587d8478fcc68c09e2506a7cf08b2817c0")
	is.True(!ok)

	ok = pass.IsPreferred("$s2$16384$8$1$iEdwbgXyKa5GNGNW/0NsOA$9YN/hzbskVVDZ887ppqv5su0n8SxVXwDB/rhVhAc9xQ")
	is.True(ok)

	ok = pass.IsPreferred("$s2$16384$7$1$iEdwbgXyKa5GNGNW/0NsOA$9YN/hzbskVVDZ887ppqv5su0n8SxVXwDB/rhVhAc9xQ")
	is.True(!ok)

	ok = pass.IsPreferred("$1$76a2173be6393254e72ffa4d6df1030a")
	is.True(!ok)
}
