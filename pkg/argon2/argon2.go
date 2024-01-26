package argon2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"

	"go.sour.is/passwd"
)

type argon struct {
	version uint8
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32

	name  string
	keyFn func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte
}

var All = []passwd.Passwder{Argon2i, Argon2id}

// Argon2i sets default recommended values.
var Argon2i = NewArgon2i(3, 32*1024, 4, 32, 16)

// Argon2id sets default recommended values.
var Argon2id = NewArgon2id(1, 64*1024, 4, 32, 16)

// NewArgon2i creates a new
func NewArgon2i(
	time uint32,
	memory uint32,
	threads uint8,
	keyLen uint32,
	saltLen uint32,
) *argon {
	return &argon{
		version: argon2.Version,
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
		saltLen: saltLen,
		name:    "argon2i",
		keyFn:   argon2.Key,
	}
}

// NewArgon2i creates a new
func NewArgon2id(
	time uint32,
	memory uint32,
	threads uint8,
	keyLen uint32,
	saltLen uint32,
) *argon {
	return &argon{
		version: argon2.Version,
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
		saltLen: saltLen,
		name:    "argon2id",
		keyFn:   argon2.IDKey,
	}
}

func (p *argon) Passwd(pass, check []byte) ([]byte, error) {
	var args *pwArgs
	var err error

	if check == nil {
		args = p.defaultArgs()
		_, err := rand.Read(args.salt)
		if err != nil {
			return nil, err
		}
		args.hash = p.keyFn(pass, args.salt, args.time, args.memory, args.threads, args.keyLen)
	} else {
		args, err = p.parseArgs(check)
		if err != nil {
			return nil, err
		}
		hash := p.keyFn(pass, args.salt, args.time, args.memory, args.threads, args.keyLen)

		if subtle.ConstantTimeCompare(hash, args.hash) == 0 {
			return nil, passwd.ErrNoMatch
		}
	}

	return args.Bytes(), nil
}
func (p *argon) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register(p.name, p)
}
func (s *argon) IsPreferred(hash []byte) bool {
	args, err := s.parseArgs(hash)
	if err != nil {
		return false
	}

	if args.version < s.version {
		return false
	}
	if args.time < s.time {
		return false
	}
	if args.memory < s.memory {
		return false
	}
	if args.threads < s.threads {
		return false
	}
	if args.keyLen < s.keyLen {
		return false
	}
	if len(args.salt) < int(s.saltLen) {
		return false
	}
	if len(args.hash) < int(s.keyLen) {
		return false
	}

	return true
}
func (p *argon) defaultArgs() *pwArgs {
	return &pwArgs{
		name:    p.name,
		version: p.version,
		time:    p.time,
		memory:  p.memory,
		threads: p.threads,
		keyLen:  p.keyLen,
		salt:    make([]byte, p.saltLen),
	}
}
func (p *argon) parseArgs(hash []byte) (*pwArgs, error) {
	pfx := []byte("$" + p.name + "$")

	if !bytes.HasPrefix(hash, pfx) {
		return nil, fmt.Errorf("%w: missing prefix", passwd.ErrBadHash)
	}
	hash = bytes.TrimPrefix(hash, pfx)
	args, hash, ok := bytes.Cut(hash, []byte("$"))
	if !ok {
		return nil, fmt.Errorf("%w: missing args", passwd.ErrBadHash)
	}
	salt, hash, ok := bytes.Cut(hash, []byte("$"))
	if !ok {
		return nil, fmt.Errorf("%w: missing salt", passwd.ErrBadHash)
	}

	var err error
	pass := p.defaultArgs()

	pass.salt = make([]byte, base64.RawStdEncoding.DecodedLen(len(salt)))
	_, err = base64.RawStdEncoding.Decode(pass.salt, salt)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt salt part", passwd.ErrBadHash)
	}

	pass.hash = make([]byte, base64.RawStdEncoding.DecodedLen(len(hash)))
	_, err = base64.RawStdEncoding.Decode(pass.hash, hash)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt hash part", passwd.ErrBadHash)
	}

	pass.name = p.name
	pass.keyLen = uint32(len(pass.hash))

	for _, part := range bytes.Split(args, []byte(",")) {
		if k, v, ok := bytes.Cut(part, []byte("=")); ok {
			switch string(k) {
			case "v":
				if i, err := strconv.ParseUint(string(v), 10, 8); err == nil {
					pass.version = uint8(i)
				}
			case "m":
				if i, err := strconv.ParseUint(string(v), 10, 32); err == nil {
					pass.memory = uint32(i)
				}
			case "t":
				if i, err := strconv.ParseUint(string(v), 10, 32); err == nil {
					pass.time = uint32(i)
				}
			case "p":
				if i, err := strconv.ParseUint(string(v), 10, 8); err == nil {
					pass.threads = uint8(i)
				}
			}
		}
	}

	return pass, nil
}

type pwArgs struct {
	name    string
	version uint8
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	salt    []byte
	hash    []byte
}

func (p *pwArgs) Bytes() []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "$%s$v=%d,m=%d,t=%d,p=%d$", p.name, p.version, p.memory, p.time, p.threads)

	salt := make([]byte, base64.RawURLEncoding.EncodedLen(len(p.salt)))
	base64.RawStdEncoding.Encode(salt, p.salt)
	b.Write(salt)

	hash := make([]byte, base64.RawURLEncoding.EncodedLen(len(p.hash)))
	base64.RawStdEncoding.Encode(hash, p.hash)
	b.WriteRune('$')
	b.Write(hash)

	return b.Bytes()
}
