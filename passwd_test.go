package passwd_test

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/sour-is/go-passwd"
	"github.com/sour-is/go-passwd/pkg/unix"
)

type plainPasswd struct{}

func (p *plainPasswd) Passwd(pass string, check string) (string, error) {
	if check == "" {
		return fmt.Sprint("$plain$", pass), nil
	}

	if subtle.ConstantTimeCompare([]byte(pass), []byte(strings.TrimPrefix(check, "$plain$"))) == 1 {
		return check, nil
	}

	return check, passwd.ErrNoMatch
}

func (p *plainPasswd) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("plain", p)
	passwd.SetFallthrough(p)
}

func Example() {
	pass := "my_pass"
	hash := "my_pass"

	pwd := passwd.New(
		&unix.MD5{}, // first is preferred type.
		&plainPasswd{},
	)

	_, err := pwd.Passwd(pass, hash)
	if err != nil {
		fmt.Println("fail: ", err)
	}

	// Check if we want to update.
	if !pwd.IsPreferred(hash) {
		newHash, err := pwd.Passwd(pass, "")
		if err != nil {
			fmt.Println("fail: ", err)
		}

		fmt.Println("new hash:", newHash)
	}

	// Output:
	//  new hash: $1$81ed91e1131a3a5a50d8a68e8ef85fa0
}

func TestPasswdHash(t *testing.T) {
	type testCase struct {
		pass, hash string
	}

	tests := []testCase{
		{"passwd", "passwd"},
		{"passwd", "$plain$passwd"},
	}
	algos := []passwd.Passwder{&plainPasswd{}}

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
			is.Equal(hash, tt.hash)
			is.NoErr(err)
		})
	}
}

func TestPasswdIsPreferred(t *testing.T) {
	is := is.New(t)

	pass := passwd.New(&plainPasswd{})

	ok := pass.IsPreferred("$plain$passwd")
	is.True(ok)

	ok = pass.IsPreferred("$foo$passwd")
	is.True(!ok)
}
