# go-passwd
 Its a multi password type checker. Using the [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) we can identify a password hashing format from the prefix `$name$` and then dispatch the hashing or checking to its specific format.


# Example

Here is an example of usage:

```go
func Example() {
	pass := "my_pass"
	hash := "$1$81ed91e1131a3a5a50d8a68e8ef85fa0"

	pwd := passwd.New(
		argon2.Argon2id, // first is preferred type.
		&unix.MD5{},
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
	//  new hash: $argon2id$...
}
```
https://github.com/sour-is/go-passwd/blob/main/passwd_test.go#L33-L59

This shows how one would set a preferred hashing type and if the current version of ones password is not the preferred type updates it to enhance the security of the hashed password when someone logs in.


# Fallthrough

> Hold up now, that example hash doesn’t have a `$` prefix!

Well for this there is the option for a hash type to set itself as a fall through if a matching hash doesn’t exist. This is good for legacy password types that don’t follow the convention.

```go
func (p *plainPasswd) ApplyPasswd(passwd *passwd.Passwd) {
	passwd.Register("plain", p)
	passwd.SetFallthrough(p)
}
```

https://github.com/sour-is/go-passwd/blob/main/passwd_test.go#L28-L31


# Custom Preference Checks

Circling back to the `IsPreferred` method. A hasher can define its own `IsPreferred` method that will be called to check if the current hash meets the complexity requirements. This is good for updating the password hashes to be more secure over time.

```go
func (p *Passwd) IsPreferred(hash string) bool {
	_, algo := p.getAlgo(hash)
	if algo != nil && algo == p.d {

		// if the algorithm defines its own check for preference.
		if ck, ok := algo.(interface{ IsPreferred(string) bool }); ok {
			return ck.IsPreferred(hash)
		}

		return true
	}
	return false
}
```

https://github.com/sour-is/go-passwd/blob/main/passwd.go#L62-L74

Example: https://github.com/sour-is/go-passwd/blob/main/pkg/argon2/argon2.go#L104-L133
