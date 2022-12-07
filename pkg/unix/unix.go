package unix

import (
	"crypto/md5"
	"crypto/subtle"
	"fmt"

	"github.com/sour-is/go-passwd"
	"golang.org/x/crypto/bcrypt"
)

var All = []passwd.Passwder{
	&Blowfish{},
	&MD5{},
}

type MD5 struct{}

func (p *MD5) Passwd(pass string, check string) (string, error) {
	h := md5.New()
	fmt.Fprint(h, pass)

	hash := fmt.Sprintf("$1$%x", h.Sum(nil))

	return hashCheck(hash, check)
}

func (p *MD5) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("1", p)
}

type Blowfish struct{}

func (p *Blowfish) Passwd(pass string, check string) (string, error) {
	if check == "" {
		b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(check), []byte(pass))
	if err != nil {
		return "", err
	}
	return check, nil
}

func (p *Blowfish) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("2a", p)
}

// type SHA256 struct{}

// func (p *SHA256) Passwd(pass string, check string) (string, error) {
// 	h := sha256.New()
// 	fmt.Fprint(h, pass)

// 	hash := fmt.Sprintf("$5$%x", h.Sum(nil))

// 	return hashCheck(hash, check)
// }

// func (p *SHA256) ApplyPasswd(passwd *passwd.Passwd) {
// 	passwd.Register("5", p)
// }

// type SHA512 struct{}

// func (p *SHA512) Passwd(pass string, check string) (string, error) {
// 	h := sha512.New()
// 	fmt.Fprint(h, pass)

// 	hash := fmt.Sprintf("$6$%x", h.Sum(nil))

// 	return hashCheck(hash, check)
// }

// func (p *SHA512) ApplyPasswd(passwd *passwd.Passwd) {
// 	passwd.Register("6", p)
// }

func hashCheck(hash, check string) (string, error) {
	if check == "" {
		return hash, nil
	}

	if subtle.ConstantTimeCompare([]byte(hash), []byte(check)) == 1 {
		return hash, nil
	}

	return hash, passwd.ErrNoMatch
}
