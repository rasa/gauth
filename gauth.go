package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"

	//"os"
	"os/user"
	"path"
	"strings"
	"syscall"
	"time"

	//"github.com/beevik/ntp"
	"github.com/logrusorgru/aurora"
	"github.com/mattn/go-colorable"
	"golang.org/x/crypto/ssh/terminal"
)

var au aurora.Aurora

var colors = flag.Bool("colors", false, "enable or disable colors")

func init() {
	flag.Parse()
	//if ! isatty.IsTerminal(os.Stdout.Fd()) {
	//  *colors = false
	//}
	au = aurora.NewAurora(*colors)
	log.SetFlags(0)
	log.SetOutput(colorable.NewColorableStdout())
}

func normalizeSecret(sec string) string {
	noPadding := strings.ToUpper(strings.Replace(sec, " ", "", -1))
	padLength := 8 - (len(noPadding) % 8)
	if padLength < 8 {
		return noPadding + strings.Repeat("=", padLength)
	}
	return noPadding
}

func AuthCode(sec string, ts int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(sec)
	if err != nil {
		return "", err
	}
	enc := hmac.New(sha1.New, key)
	msg := make([]byte, 8, 8)
	msg[0] = (byte)(ts >> (7 * 8) & 0xff)
	msg[1] = (byte)(ts >> (6 * 8) & 0xff)
	msg[2] = (byte)(ts >> (5 * 8) & 0xff)
	msg[3] = (byte)(ts >> (4 * 8) & 0xff)
	msg[4] = (byte)(ts >> (3 * 8) & 0xff)
	msg[5] = (byte)(ts >> (2 * 8) & 0xff)
	msg[6] = (byte)(ts >> (1 * 8) & 0xff)
	msg[7] = (byte)(ts >> (0 * 8) & 0xff)
	if _, err := enc.Write(msg); err != nil {
		return "", err
	}
	hash := enc.Sum(nil)
	offset := hash[19] & 0x0f
	trunc := hash[offset : offset+4]
	trunc[0] &= 0x7F
	res := new(big.Int).Mod(new(big.Int).SetBytes(trunc), big.NewInt(1000000))
	return fmt.Sprintf("%06d", res), nil
}

func authCodeOrDie(sec string, ts int64) string {
	str, e := AuthCode(sec, ts)
	if e != nil {
		log.Fatal(e)
	}
	return str
}

func main() {
	user, e := user.Current()
	if e != nil {
		log.Fatal(e)
	}
	csvFile := "gauth.csv"
	cfgPath := path.Join(user.HomeDir, ".config/"+csvFile)

	cfgContent, e := ioutil.ReadFile(cfgPath)
	if e != nil {
		log.Fatal(e)
	}

	// Support for 'openssl enc -aes-128-cbc -md sha256 -pass pass:'
	if bytes.Compare(cfgContent[:8], []byte{0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f}) == 0 {
		fmt.Printf("Encryption password: ")
		passwd, e := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if e != nil {
			log.Fatal(e)
		}
		salt := cfgContent[8:16]
		rest := cfgContent[16:]
		salting := sha256.New()
		salting.Write([]byte(passwd))
		salting.Write(salt)
		sum := salting.Sum(nil)
		key := sum[:16]
		iv := sum[16:]
		block, e := aes.NewCipher(key)
		if e != nil {
			log.Fatal(e)
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(rest, rest)
		// Remove padding
		i := len(rest) - 1
		for rest[i] < 16 {
			i--
		}
		cfgContent = rest[:i]
	}

	cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
	// Unix-style tabular
	cfgReader.Comma = ':'

	cfg, e := cfgReader.ReadAll()
	if e != nil {
		log.Fatal(e)
	}

	now := time.Now()
	/*options := ntp.QueryOptions{Timeout: 1 * time.Second}
		response, err := ntp.QueryWithOptions("pool.ntp.org", options)
		ify err != nil {
			fmt.Printf("err=%v", err)
			os.Exit(1)
		} else {
			fmt.Printf("response.ClockOffset=%v\n", response.ClockOffset)
			now = now.Add(response.ClockOffset)
	  }
	*/
	// align with Google Authenticator & Authy
	//anow := now.Add(-2 * time.Second)
	time := now.Unix()
	currentTS := time / 30
	progress := int(time % 30)

	prevTS := currentTS - 1
	nextTS := currentTS + 1

	stime := now.Format("15:04:05")
	account := fmt.Sprintf("%s %s", stime, csvFile)
	width := len(account)
	for _, record := range cfg {
		if len(record[0]) > width {
			width = len(record[0])
		}
	}

	sfmt := "%-*.*s %6s %6s %6s"

	type ColorFunc func(interface{}) aurora.Value
	funcs := []ColorFunc{au.BrightWhite, au.BrightMagenta, au.BrightCyan, au.BrightGreen, au.BrightYellow, au.BrightRed}
	n := int64(len(funcs))
	prevMod := prevTS % n
	currMod := currentTS % n
	nextMod := nextTS % n
	cname := au.BrightWhite(account).Underline()
	prev := funcs[prevMod]("-30s").Underline()
	curr := funcs[currMod]("now").Underline()
	next := funcs[nextMod]("+30s").Underline()

	log.Printf(sfmt+"\n", width, width, cname, prev, curr, next)
	for _, record := range cfg {
		name := record[0]
		cname = au.White(name)
		secret := normalizeSecret(record[1])
		prevToken := authCodeOrDie(secret, prevTS)
		currentToken := authCodeOrDie(secret, currentTS)
		nextToken := authCodeOrDie(secret, nextTS)
		prev = funcs[prevMod](prevToken)
		curr = funcs[currMod](currentToken)
		next = funcs[nextMod](nextToken)
		s := fmt.Sprintf(sfmt, width, width, cname, prev, curr, next)
		log.Print(s)
	}
	nwidth := width
	if nwidth > 34 {
		nwidth = 34
	}
	left := 30 - progress
	sleft := fmt.Sprintf("%2d", left)
	gap := nwidth - 4
	equals := progress + 1
	if gap < 30 {
		equals -= 30 - gap
	}
	if equals < 0 {
		equals = 0
	}
	bar := fmt.Sprintf("[%s%*s]", sleft, -gap, strings.Repeat("=", equals))
	barlen := len(bar)
	var cbar aurora.Value

	switch {
	case progress < 20:
		cbar = au.BrightGreen(bar)
	case progress < 25:
		cbar = au.BrightYellow(bar)
	default:
		cbar = au.BrightRed(bar)
	}
	prevID := prevTS%100 + 1
	currID := currentTS%100 + 1
	nextID := nextTS%100 + 1
	dfuncs := []ColorFunc{au.White, au.Magenta, au.Cyan, au.Green, au.Yellow, au.Red}
	shift := progress - 25
	if shift < 0 {
		shift = 0
	}
	spaces := strings.Repeat(" ", 5-shift)
	s := fmt.Sprintf("%*s%s%2d %6d %6d%s", -barlen, cbar, spaces, dfuncs[prevMod](prevID), dfuncs[currMod](currID), dfuncs[nextMod](nextID), au.White(""))
	log.Print(s)
}
