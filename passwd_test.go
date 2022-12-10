package passwd_test

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"testing"

	"github.com/matryer/is"
	"github.com/sour-is/go-passwd"
	"github.com/sour-is/go-passwd/pkg/argon2"
	"github.com/sour-is/go-passwd/pkg/unix"
)

type plainPasswd struct{}

func (p *plainPasswd) Passwd(pass, check []byte) ([]byte, error) {
	if check == nil {
		var b bytes.Buffer
		b.WriteString("$plain$")
		b.Write(pass)
		return b.Bytes(), nil
	}

	if subtle.ConstantTimeCompare([]byte(pass), []byte(bytes.TrimPrefix(check, []byte("$plain$")))) == 1 {
		return check, nil
	}

	return check, passwd.ErrNoMatch
}

func (p *plainPasswd) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("plain", p)
	passwd.SetFallthrough(p)
}

// Example of upgrading password hash to a greater complexity.
//
// Note: This example uses very unsecure hash functions to allow for predictable output. Use of argon2.Argon2id or scrypt.Scrypt2 for greater hash security is recommended.
func Example() {
	pass := []byte("my_pass")
	hash := []byte("$1$81ed91e1131a3a5a50d8a68e8ef85fa0")

	pwd := passwd.New(
		argon2.Argon2id, // first is preferred type.
		&unix.MD5{},
	)

	_, err := pwd.Passwd(pass, hash)
	if err != nil {
		fmt.Println("fail: ", err)
		return
	}

	// Check if we want to update.
	if !pwd.IsPreferred(hash) {
		newHash, err := pwd.Passwd(pass, nil)
		if err != nil {
			fmt.Println("fail: ", err)
			return
		}

		fmt.Println("new hash:", string(newHash)[:31], "...")
	}

	// Output:
	//  new hash: $argon2id$v=19,m=65536,t=1,p=4$ ...
}

func TestPasswdHash(t *testing.T) {
	type testCase struct {
		pass, hash []byte
	}

	tests := []testCase{
		{[]byte("passwd"), []byte("passwd")},
		{[]byte("passwd"), []byte("$plain$passwd")},
	}
	algos := []passwd.Passwder{&plainPasswd{}}

	is := is.New(t)
	// Generate additional test cases for each algo.
	for _, algo := range algos {
		hash, err := algo.Passwd([]byte("passwd"), nil)
		is.NoErr(err)
		tests = append(tests, testCase{[]byte("passwd"), hash})
	}

	pass := passwd.New(algos...)

	for i, tt := range tests {
		t.Run(fmt.Sprint("Test-", i), func(t *testing.T) {
			is := is.New(t)

			hash, err := pass.Passwd(tt.pass, tt.hash)
			is.Equal(hash, tt.hash)
			is.NoErr(err)
		})
	}
}

func TestPasswdIsPreferred(t *testing.T) {
	is := is.New(t)

	pass := passwd.New(&plainPasswd{})

	ok := pass.IsPreferred([]byte("$plain$passwd"))
	is.True(ok)

	ok = pass.IsPreferred([]byte("$foo$passwd"))
	is.True(!ok)
}
