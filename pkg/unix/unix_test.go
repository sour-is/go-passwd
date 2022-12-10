package unix_test

import (
	"fmt"
	"testing"

	"github.com/matryer/is"

	"github.com/sour-is/go-passwd"
	"github.com/sour-is/go-passwd/pkg/unix"
)

func TestPasswdHash(t *testing.T) {
	type testCase struct {
		pass, hash []byte
	}

	tests := []testCase{
		{[]byte("passwd"), []byte("$1$76a2173be6393254e72ffa4d6df1030a")},
		{[]byte("passwd"), []byte("$2a$10$GkJwB.nOaaeAvRGgyl2TI.kruM8e.iIo.OozgdslegpNlC/vIFKRq")},
	}

	is := is.New(t)
	// Generate additional test cases for each algo.
	for _, algo := range unix.All {
		hash, err := algo.Passwd([]byte("passwd"), nil)
		is.NoErr(err)
		tests = append(tests, testCase{[]byte("passwd"), hash})
	}

	pass := passwd.New(unix.All...)

	for i, tt := range tests {
		t.Run(fmt.Sprint("Test-", i), func(t *testing.T) {
			is := is.New(t)

			hash, err := pass.Passwd(tt.pass, tt.hash)
			is.Equal(string(hash), string(tt.hash))
			is.NoErr(err)
		})
	}
}
