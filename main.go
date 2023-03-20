package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/sshmarshal"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

var (
	prefix                     = ""
	numThreads                 = 1
	startTime                  = time.Now()
	expectedNumOfKeys          = uint64(0)
	expectedNumOfKeys50Percent = uint64(0)
	expectedNumOfKeys75Percent = uint64(0)
)

func main() {
	if len(os.Args) > 2 {
		prefix = os.Args[1]
		var err error
		numThreads, err = strconv.Atoi(os.Args[2])
		if err != nil {
			panic(err)
		}
		if numThreads < 1 {
			fmt.Println("error: number of threads must be at least 1")
			return
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

	doStatistics()

	done := make(chan bool)
	fmt.Println("Starting " + strconv.Itoa(numThreads) + " threads. Expected number of tries for a prefix of this length: " + color.YellowString(format(expectedNumOfKeys)))
	for i := 0; i < numThreads; i++ {
		go worker(done, i+1)
	}
	<-done
}

// https://www.desmos.com/calculator/vfm9tut95c
func doStatistics() {
	expectedNumOfKeys = uint64(1) << uint64(len(prefix)*4) // 16^len(prefix)
	oneMinusP := (float64(expectedNumOfKeys) - 1) / float64(expectedNumOfKeys)
	expectedNumOfKeys50Percent = uint64(math.Log2(0.5) / math.Log2(oneMinusP))
	expectedNumOfKeys75Percent = uint64(math.Log2(1-0.75) / math.Log2(oneMinusP))
}

var updateDuration = 2 * time.Second

func worker(done chan bool, threadNum int) {
	i := bytesToBigint(getRandBytes32())
	key := make([]byte, 32)
	oneAsBigint := big.NewInt(1)
	keysTried := uint64(0)
	if threadNum == 1 {
		go func() {
			isFirstRun := true
			for {
				keysTriedLastTime := keysTried
				time.Sleep(updateDuration)
				if isFirstRun {
					fmt.Print("\n\n")
					isFirstRun = false
				}
				currSpeed := float64(numThreads) * float64(keysTried-keysTriedLastTime) / (updateDuration.Seconds()) // approx keys/s
				//timeLeft := (float64(expectedNumOfKeys) - float64(numThreads)*float64(keysTried)) / currSpeed        // approx seconds
				timeLeft50 := time.Duration((float64(expectedNumOfKeys50Percent) - float64(numThreads)*float64(keysTried)) / currSpeed * float64(time.Second))
				timeLeft75 := time.Duration((float64(expectedNumOfKeys75Percent) - float64(numThreads)*float64(keysTried)) / currSpeed * float64(time.Second))
				fmt.Printf("\u001B[A\u001B[2K\rCurrent speed: %.1f keys/ms. 50%% - 75%% chance of being done in: %s - %s\n", currSpeed/1000, color.YellowString(timeLeft50.Round(time.Millisecond*100).String()), color.YellowString(timeLeft75.Round(time.Millisecond*100).String()))
			}
		}()
	}
	for ; ; keysTried++ {
		priv, sshpub, id := genKey(i.FillBytes(key))
		if strings.HasPrefix(id, prefix) {
			fmt.Print("\nFound key with id: ")
			color.Yellow(id + "\n\nPrivate key: ")
			blk, err := sshmarshal.MarshalPrivateKey(priv, "")
			if err != nil {
				panic(err)
			}
			pem.Encode(os.Stdout, blk)
			color.Yellow("\nPublic key: ")
			fmt.Println(string(ssh.MarshalAuthorizedKey(sshpub)))
			fmt.Printf("Took %s and approximately %s tries. Expected to take %s on average\n", color.YellowString(time.Since(startTime).Round(time.Millisecond*100).String()), color.YellowString(format(keysTried*uint64(numThreads))), color.YellowString(format(expectedNumOfKeys)))
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

// from https://stackoverflow.com/a/31046325
func format(n uint64) string {
	in := strconv.FormatUint(n, 10)
	numOfDigits := len(in)
	numOfCommas := (numOfDigits - 1) / 3
	out := make([]byte, len(in)+numOfCommas)
	for i, j, k := len(in)-1, len(out)-1, 0; ; i, j = i-1, j-1 {
		out[j] = in[i]
		if i == 0 {
			return string(out)
		}
		if k++; k == 3 {
			j, k = j-1, 0
			out[j] = ','
		}
	}
}
