// 2fa provides a simple end-to-end example of server side support for google authenticator.
// It sets up a secret for a single user, generates a QR code as a PNG file that the user
// can scan into Google Authenticator, and then prompts the user for a token that the user
// copies from the Authenticator app. We validate the token and print out whether it is valid or not.
package main

import (
	// "crypto/rand"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	dgoogauth "github.com/dgryski/dgoogauth"
	qr "rsc.io/qr"
)

const (
	qrFilename = "qr.png"
)

func main() {
	// Example secret from here:
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	// secret := []byte{'=', '!', '&', '?', 'S', 'd', 'p', 'u', '6', 'x', 'n', 'B', '8', 'F', 'v', 'n', 0xDE, 0xAD, 0xBE, 0xEF}

	// Generate random secret instead of using the test value above.
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	account := "example@email.com"
	issuer := "CurrentAdminService"

	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		panic(err)
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Add("secret", secretBase32)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	fmt.Printf("URL is %s\n", URL.String())

	code, err := qr.Encode(URL.String(), qr.Q)
	if err != nil {
		panic(err)
	}
	b := code.PNG()
	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	fmt.Println(path + qrFilename)

	err = ioutil.WriteFile(path+"/"+qrFilename, b, 0600)
	if err != nil {
		panic(err)
	}

	fmt.Printf("QR code is in %s. Please scan it into Google Authenticator app.\n", qrFilename)

	// The OTPConfig gets modified by otpc.Authenticate() to prevent passcode replay, etc.,
	// so allocate it once and reuse it for multiple calls.
	otpc := &dgoogauth.OTPConfig{
		Secret:      secretBase32,
		WindowSize:  3,
		HotpCounter: 0,
		// UTC:         true,
	}

	for {
		var token string
		fmt.Printf("Please enter the token value (or q to quit): ")
		fmt.Scanln(&token)

		if token == "q" {
			break
		}

		val, err := otpc.Authenticate(token)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if !val {
			fmt.Println("Sorry, Not Authenticated")
			continue
		}

		fmt.Println("Authenticated!")
	}
	return
}
