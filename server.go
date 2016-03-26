package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

var INTMAX int = 2147483647

func CTREncrypt(plaintext []byte) (ciphertext []byte, err error) {

	randBytes := func() (bytes []byte, err error) {
		bytes = make([]byte, 16)
		n, err := rand.Read(bytes)
		if err != nil || n != 16 {
			return []byte{}, err
		}
		return bytes, nil
	}

	key, err1 := randBytes()
	iv, err2 := randBytes()

	if err1 != nil || err2 != nil {
		return []byte{}, err1
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return []byte{}, err
	}

	ciphertext = make([]byte, len(plaintext))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil

}

func CompressionOracle(payload string) int {
	request := FormatRequest(payload)
	var compressedPayload bytes.Buffer
	compressor := zlib.NewWriter(&compressedPayload)
	compressor.Write([]byte(request))
	compressor.Close()
	ciphertext, err := CTREncrypt(compressedPayload.Bytes())
	if err != nil {
		return 0
	}
	return len(ciphertext)
}

func FormatRequest(payload string) (request string) {
	template := `POST / HTTP/1.1
	Host: hapless.com
	Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
	Content-Length: %d
	%s`
	request = fmt.Sprintf(template, len(payload), payload)
	return request
}

func IsValidBase64(input string) bool {
	if len(input) == 0 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return false
	}
	return true
}

func Attack() {

	knowPrefix := "sessionid="
	//The target cookie name is known data.
	knownData := knowPrefix
	//The target cookie value is base64 encoded data.
	characterSet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	fmt.Printf("Starting attack.\n")
	fmt.Printf("Known data: %s", knownData)

	for !IsValidBase64(knownData[len(knowPrefix):]) {
		smallestGuessSize := INTMAX
		smallestGuess := "\x00"
		for i := 0; i < len(characterSet); i++ {
			guess := string(characterSet[i])
			guessSize := CompressionOracle(knownData + guess)
			if guessSize < smallestGuessSize {
				smallestGuess = guess
				smallestGuessSize = guessSize
			}
		}

		if smallestGuessSize == INTMAX {
			fmt.Printf("\nThere was an error.\n")
		} else {
			knownData += smallestGuess
			fmt.Printf("%s", smallestGuess)
		}
	}
	fmt.Printf("\n")
}

func main() {
	Attack()
}
