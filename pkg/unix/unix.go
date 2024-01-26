package unix

import (
	"crypto/md5"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"go.sour.is/passwd"
)

var All = []passwd.Passwder{
	&Blowfish{},
	&MD5{},
}

type MD5 struct{}

func (p *MD5) Passwd(pass, check []byte) ([]byte, error) {
	h := md5.New()
	h.Write(pass)

	hash := []byte(fmt.Sprintf("$1$%x", h.Sum(nil)))

	return hashCheck(hash, check)
}

func (p *MD5) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("1", p)
}

type Blowfish struct{}

func (p *Blowfish) Passwd(pass, check []byte) ([]byte, error) {
	if check == nil {
		b, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	err := bcrypt.CompareHashAndPassword(check, pass)
	if err != nil {
		return nil, err
	}
	return check, nil
}

func (p *Blowfish) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("2a", p)
}

func hashCheck(hash, check []byte) ([]byte, error) {
	if check == nil {
		return hash, nil
	}

	if subtle.ConstantTimeCompare(hash, check) == 1 {
		return hash, nil
	}

	return hash, passwd.ErrNoMatch
}
