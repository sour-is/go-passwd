package scrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"

	"go.sour.is/passwd"
	"golang.org/x/crypto/scrypt"
)

type scryptpw struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelization parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)

	name    string
	encoder interface {
		EncodedLen(n int) int
		Encode(dst, src []byte)
		DecodedLen(x int) int
		Decode(dst, src []byte) (n int, err error)
	}
}
type scryptArgs struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelization parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)

	name string
	salt []byte
	hash []byte

	encoder interface {
		EncodedLen(n int) int
		Encode(dst, src []byte)
		DecodedLen(x int) int
		Decode(dst, src []byte) (n int, err error)
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

func (s *scryptpw) Passwd(pass, check []byte) ([]byte, error) {
	var args *scryptArgs
	var err error

	if check == nil {
		args = s.defaultArgs()
		_, err := rand.Read(args.salt)
		if err != nil {
			return nil, err
		}
		args.hash, err = scrypt.Key(pass, args.salt, args.N, args.R, args.P, args.DKLen)
		if err != nil {
			return nil, err
		}

	} else {
		args, err = s.parseArgs(check)
		if err != nil {
			return nil, err
		}
		hash, err := scrypt.Key([]byte(pass), args.salt, args.N, args.R, args.P, args.DKLen)
		if err != nil {
			return nil, err
		}

		if subtle.ConstantTimeCompare(hash, args.hash) == 0 {
			return nil, passwd.ErrNoMatch
		}
	}

	return args.Bytes(), nil
}
func (s *scryptpw) ApplyPasswd(p *passwd.Passwd) {
	p.Register(s.name, s)
	if s.name == "s1" {
		p.SetFallthrough(s)
	}
}
func (s *scryptpw) IsPreferred(hash []byte) bool {
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

func (s *scryptpw) parseArgs(hash []byte) (*scryptArgs, error) {
	args := s.defaultArgs()

	name := []byte("$" + s.name + "$")
	hash = bytes.TrimPrefix(hash, name)

	N, hash, ok := bytes.Cut(hash, []byte("$"))
	if !ok {
		return nil, fmt.Errorf("%w: missing args: N", passwd.ErrBadHash)
	}
	if n, err := strconv.Atoi(string(N)); err == nil {
		args.N = n
	}

	R, hash, ok := bytes.Cut(hash, []byte("$"))
	if !ok {
		return nil, fmt.Errorf("%w: missing args: R", passwd.ErrBadHash)
	}
	if r, err := strconv.Atoi(string(R)); err == nil {
		args.R = r
	}

	P, hash, ok := bytes.Cut(hash, []byte("$"))
	if !ok {
		return nil, fmt.Errorf("%w: missing args: P", passwd.ErrBadHash)
	}
	if p, err := strconv.Atoi(string(P)); err == nil {
		args.P = p
	}

	salt, hash, ok := bytes.Cut(hash, []byte("$"))
	if !ok {
		return nil, fmt.Errorf("%w: missing args: salt", passwd.ErrBadHash)
	}

	var err error
	args.salt = make([]byte, s.encoder.DecodedLen(len(salt)))
	_, err = s.encoder.Decode(args.salt, salt)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt salt part", passwd.ErrBadHash)
	}
	args.SaltLen = len(args.salt)

	args.hash = make([]byte, s.encoder.DecodedLen(len(hash)))
	_, err = s.encoder.Decode(args.hash, hash)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt hash part", passwd.ErrBadHash)
	}
	args.DKLen = len(args.hash)

	return args, nil
}

func (s *scryptArgs) Bytes() []byte {
	var b bytes.Buffer

	if s.name != "s1" {
		b.WriteRune('$')
		b.WriteString(s.name)
		b.WriteRune('$')
	}

	fmt.Fprintf(&b, "%d$%d$%d", s.N, s.R, s.P)

	salt := make([]byte, s.encoder.EncodedLen(len(s.salt)))
	s.encoder.Encode(salt, s.salt)
	b.WriteRune('$')
	b.Write(salt)

	hash := make([]byte, s.encoder.EncodedLen(len(s.hash)))
	s.encoder.Encode(hash, s.hash)
	b.WriteRune('$')
	b.Write(hash)

	return b.Bytes()
}

type hexenc struct{}

func (hexenc) Encode(dst, src []byte) {
	hex.Encode(dst, src)
}
func (hexenc) EncodedLen(n int) int { return hex.EncodedLen(n) }
func (hexenc) Decode(dst, src []byte) (n int, err error) {
	return hex.Decode(dst, src)
}
func (hexenc) DecodedLen(x int) int { return hex.DecodedLen(x) }
