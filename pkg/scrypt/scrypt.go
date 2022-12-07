package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/sour-is/go-passwd"
	"golang.org/x/crypto/scrypt"
)

type scryptpw struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelisation parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)

	name    string
	encoder interface {
		EncodeToString(src []byte) string
		DecodeString(s string) ([]byte, error)
	}
}
type scryptArgs struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelisation parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)

	name string
	salt []byte
	hash []byte

	encoder interface {
		EncodeToString(src []byte) string
		DecodeString(s string) ([]byte, error)
	}
}

var All = []passwd.Passwder{Simple, Scrypt2}

var Simple = &scryptpw{
	N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32,
	name: "s1", encoder: hexenc{},
}

var Scrypt2 = &scryptpw{
	N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32,
	name: "s2", encoder: base64.RawStdEncoding,
}

func (s *scryptpw) Passwd(pass string, check string) (string, error) {
	var args *scryptArgs
	var err error

	if check == "" {
		args = s.defaultArgs()
		_, err := rand.Read(args.salt)
		if err != nil {
			return "", err
		}
		args.hash, err = scrypt.Key([]byte(pass), args.salt, args.N, args.R, args.P, args.DKLen)
		if err != nil {
			return "", err
		}

	} else {
		args, err = s.parseArgs(check)
		if err != nil {
			return "", err
		}
		hash, err := scrypt.Key([]byte(pass), args.salt, args.N, args.R, args.P, args.DKLen)
		if err != nil {
			return "", err
		}

		if subtle.ConstantTimeCompare(hash, args.hash) == 0 {
			return "", passwd.ErrNoMatch
		}
	}

	return args.String(), nil
}
func (s *scryptpw) ApplyPasswd(p *passwd.Passwd) {
	p.Register(s.name, s)
	if s.name == "s1" {
		p.SetFallthrough(s)
	}
}
func (s *scryptpw) IsPreferred(hash string) bool {
	args, err := s.parseArgs(hash)
	if err != nil {
		return false
	}

	if args.N < s.N {
		return false
	}
	if args.R < s.R {
		return false
	}
	if args.P < s.P {
		return false
	}
	if args.SaltLen < s.SaltLen {
		return false
	}
	if args.DKLen < s.DKLen {
		return false
	}

	return true
}
func (s *scryptpw) defaultArgs() *scryptArgs {
	return &scryptArgs{
		name:    s.name,
		N:       s.N,
		R:       s.R,
		P:       s.P,
		DKLen:   s.DKLen,
		SaltLen: s.SaltLen,
		salt:    make([]byte, s.SaltLen),
		encoder: s.encoder,
	}
}
func (s *scryptpw) parseArgs(hash string) (*scryptArgs, error) {
	args := s.defaultArgs()

	name := "$" + s.name + "$"
	hash = strings.TrimPrefix(hash, name)

	N, hash, ok := strings.Cut(hash, "$")
	if !ok {
		return nil, fmt.Errorf("%w: missing args: N", passwd.ErrBadHash)
	}
	if n, err := strconv.Atoi(N); err == nil {
		args.N = n
	}

	R, hash, ok := strings.Cut(hash, "$")
	if !ok {
		return nil, fmt.Errorf("%w: missing args: R", passwd.ErrBadHash)
	}
	if r, err := strconv.Atoi(R); err == nil {
		args.R = r
	}

	P, hash, ok := strings.Cut(hash, "$")
	if !ok {
		return nil, fmt.Errorf("%w: missing args: P", passwd.ErrBadHash)
	}
	if p, err := strconv.Atoi(P); err == nil {
		args.P = p
	}

	salt, hash, ok := strings.Cut(hash, "$")
	if !ok {
		return nil, fmt.Errorf("%w: missing args: salt", passwd.ErrBadHash)
	}

	var err error
	args.salt, err = s.encoder.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt salt part", passwd.ErrBadHash)
	}
	args.SaltLen = len(args.salt)

	args.hash, err = s.encoder.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt hash part", passwd.ErrBadHash)
	}
	args.DKLen = len(args.hash)

	return args, nil
}
func (s *scryptArgs) String() string {
	var name string
	if s.name != "s1" {
		name = "$" + s.name + "$"
	}
	salt := s.encoder.EncodeToString(s.salt)
	hash := s.encoder.EncodeToString(s.hash)

	return fmt.Sprintf("%s%d$%d$%d$%s$%s", name, s.N, s.R, s.P, salt, hash)
}

type hexenc struct{}

func (hexenc) EncodeToString(src []byte) string {
	return hex.EncodeToString(src)
}
func (hexenc) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
