package passwd

import (
	"errors"
	"fmt"
	"strings"
)

type Passwder interface {
	Passwd(string, string) (string, error)
	ApplyPasswd(*Passwd)
}

type Passwd struct {
	m map[string]Passwder
	d Passwder
	f Passwder
}

func New(opts ...Passwder) *Passwd {
	p := &Passwd{m: make(map[string]Passwder)}
	p.Options(opts...)

	return p
}

func (p *Passwd) Options(opts ...Passwder) {
	for _, o := range opts {
		o.ApplyPasswd(p)
	}
}

func (p *Passwd) Register(name string, pass Passwder) {
	p.m[name] = pass
	if p.d == nil {
		p.SetDefault(pass)
	}
}

func (p *Passwd) SetDefault(pass Passwder) {
	p.d = pass
}

func (p *Passwd) SetFallthrough(pass Passwder) {
	p.f = pass
}

func (p *Passwd) Passwd(pass, hash string) (string, error) {
	if hash == "" {
		return p.d.Passwd(pass, hash)
	}
	name, algo := p.getAlgo(hash)
	if algo == nil {
		algo = p.f
	}
	if algo == nil {
		return "", fmt.Errorf("%w: %s", ErrNoHandler, name)
	}
	return algo.Passwd(pass, hash)
}

func (p *Passwd) IsPreferred(hash string) bool {
	_, algo := p.getAlgo(hash)
	if algo != nil && algo == p.d {
		return true
	}
	return false
}

func (p *Passwd) getAlgo(hash string) (string, Passwder) {
	var algo string
	if _, h, ok := strings.Cut(hash, "$"); ok {
		algo, _, ok = strings.Cut(h, "$")
		if !ok {
			return "", nil
		}

		if passwd, ok := p.m[algo]; ok {
			return algo, passwd
		}

		return algo, nil
	}

	return p.getName(p.f), p.f
}

func (p *Passwd) getName(n Passwder) string {
	if n == nil {
		return ""
	}
	for k, v := range p.m {
		if v == n {
			return k
		}
	}
	return "none"
}

var ErrNoMatch = errors.New("password does not match")
var ErrBadHash = errors.New("password hash is malformed")
var ErrNoHandler = errors.New("password handler not registered")
