package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/caarlos0/sshmarshal"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

var (
	prefix     = ""
	numThreads = 1
)

func main() {
	if len(os.Args) > 2 {
		prefix = os.Args[1]
		var err error
		numThreads, err = strconv.Atoi(os.Args[2])
		if err != nil {
			panic(err)
		}
	} else if len(os.Args) > 1 {
		prefix = os.Args[1]
	} else {
		fmt.Println("error: need at least one argument.\nUsage:\n   ./mineid <prefix> [<num of threads>]")
		return
	}

	trimmed := prefix
	for _, r := range "0123456789abcdef" {
		trimmed = strings.ReplaceAll(trimmed, string(r), "")
	}
	if trimmed != "" {
		if len(trimmed) == 1 {
			fmt.Println("error: prefix contains this non-hex character: " + trimmed)
		} else {
			fmt.Println("error: prefix contains these non-hex characters: " + trimmed)
		}
		return
	}

	done := make(chan bool)
	for i := 0; i < numThreads; i++ {
		go worker(done)
	}
	<-done
}

func worker(done chan bool) {
	i := bytesToBigint(getRandBytes32())
	key := make([]byte, 32)
	oneAsBigint := big.NewInt(1)
	for {
		priv, sshpub, id := genKey(i.FillBytes(key))
		if strings.HasPrefix(id, prefix) {
			fmt.Print("Found key with id: ")
			color.Yellow(id + "\nPrivate key: ")
			blk, err := sshmarshal.MarshalPrivateKey(priv, "")
			if err != nil {
				panic(err)
			}
			pem.Encode(os.Stdout, blk)
			color.Yellow("\nPublic key: ")
			fmt.Println(string(ssh.MarshalAuthorizedKey(sshpub)))
			done <- true
			break
		}
		i.Add(i, oneAsBigint)
	}
}

func getRandBytes32() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func bytesToBigint(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func genKey(s []byte) (privkey ed25519.PrivateKey, sshpubkey ssh.PublicKey, id string) {
	priv := ed25519.NewKeyFromSeed(s)
	pub := priv.Public().(ed25519.PublicKey)
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return priv, sshPubKey, shasum(sshPubKey.Marshal())
}

func shasum(a []byte) string {
	s := sha256.New()
	s.Write(a)
	return hex.EncodeToString(s.Sum(nil))
}
