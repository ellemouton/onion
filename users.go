package onion

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"strings"
)

const (
	Alice   = "ALICE"
	Bob     = "BOB"
	Charlie = "CHARLIE"
	Dave    = "DAVE"

	alicePk   = "ad7e16172a13b571ec8bcd4b8c76d446a8be566d972c44742f08016c066a136b"
	bobPk     = "e3e6fa3499dcbc47880c71650d3617b9d74cff3b85f295a4827a381c724804b8"
	charliePk = "08d277077c093f9ba654ddf8afd2a58a03546ef74eaf54e2434d02e8f3ebaffb"
	davePk    = "456ffe0a616b5f2dc4997ce2615d79b5f9cac126fe971ccd1372527edccf12fe"
)

var Users map[string]*User

type User struct {
	Name    string
	privKey *btcec.PrivateKey
	PubKey  *btcec.PublicKey
}

func GetUser(username string) (*User, error) {
	user, ok := Users[strings.ToUpper(username)]
	if !ok {
		return nil, fmt.Errorf("no user named %s", username)
	}

	return user, nil
}

func init() {
	Users = make(map[string]*User)

	// Read alice pubkey.
	ab, _ := hex.DecodeString(alicePk)
	priv, pub := btcec.PrivKeyFromBytes(ab)
	Users[Alice] = &User{
		Name:    Alice,
		privKey: priv,
		PubKey:  pub,
	}

	bb, _ := hex.DecodeString(bobPk)
	priv, pub = btcec.PrivKeyFromBytes(bb)
	Users[Bob] = &User{
		Name:    Bob,
		privKey: priv,
		PubKey:  pub,
	}

	cb, _ := hex.DecodeString(charliePk)
	priv, pub = btcec.PrivKeyFromBytes(cb)
	Users[Charlie] = &User{
		Name:    Charlie,
		privKey: priv,
		PubKey:  pub,
	}

	db, _ := hex.DecodeString(davePk)
	priv, pub = btcec.PrivKeyFromBytes(db)
	Users[Dave] = &User{
		Name:    Dave,
		privKey: priv,
		PubKey:  pub,
	}
}
