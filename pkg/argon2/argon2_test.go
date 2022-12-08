package argon2_test

import (
	"fmt"
	"testing"

	"github.com/matryer/is"

	"github.com/sour-is/go-passwd"
	"github.com/sour-is/go-passwd/pkg/argon2"
	"github.com/sour-is/go-passwd/pkg/unix"
)

func TestPasswdHash(t *testing.T) {
	type testCase struct {
		pass, hash string
	}

	tests := []testCase{}
	algos := argon2.All

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

	pass := passwd.New(argon2.Argon2i, &unix.MD5{})

	ok := pass.IsPreferred("$argon2i$v=19,m=32768,t=3,p=4$LdaB2Z4EI4lwpxTc78QUFw$VhlPSK0tdF226QCLC24IIrmQcMBmg47Ik9h/Yq6htFI")
	is.True(ok)

	ok = pass.IsPreferred("$argon2i$v=19,m=1024,t=2,p=4$LdaB2Z4EI4lwpxTc78QUFw$VhlPSK0tdF226QCLC24IIrmQcMBmg47Ik9h/Yq6htFI")
	is.True(!ok)

	ok = pass.IsPreferred("$1$76a2173be6393254e72ffa4d6df1030a")
	is.True(!ok)
}
