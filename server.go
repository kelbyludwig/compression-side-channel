package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

//IsValidToken simulates an request with a token. If the token is valid, we expect an "authenticated" response.
func IsValidToken(input string) bool {
	token := "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
	if input == token {
		fmt.Printf("\nYay! You got the token!\n")
		return true
	} else {
		return false
	}
}

func NaiveAttack() {

	knowPrefix := "Cookie: sessionid="
	//The target cookie name is known data.
	knownData := knowPrefix
	//The target cookie value is base64 encoded data.
	characterSet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	fmt.Printf("Starting attack.\n")
	fmt.Printf("Known data: %s", knownData)

	for !IsValidToken(knownData[len(knowPrefix):]) {

		smallestGuessSize := INTMAX
		smallestGuesses := make([]string, 0)

		for i := 0; i < len(characterSet); i++ {

			guess := string(characterSet[i])
			guessSize := CompressionOracle(knownData + guess)

			if guessSize < smallestGuessSize {
				smallestGuesses = []string{guess}
				smallestGuessSize = guessSize
				continue
			}

			if guessSize == smallestGuessSize {
				smallestGuesses = append(smallestGuesses, guess)
				smallestGuessSize = guessSize
				continue
			}
		}

		if smallestGuessSize == INTMAX || len(smallestGuesses) == 0 {
			fmt.Printf("\nThere was an error.\n")
			return
		}

		if len(smallestGuesses) == 1 {
			knownData += smallestGuesses[0]
			fmt.Printf("%s", smallestGuesses[0])
			continue
		}

		smallestGuessSize = INTMAX
		smallestGuess := "\x00"
		for _, guess := range smallestGuesses {
			multipleGuesses := ""
			for x := 0; x < 8; x++ {
				multipleGuesses += (knownData + guess)
			}
			guessSize := CompressionOracle(multipleGuesses)
			if guessSize < smallestGuessSize {
				smallestGuess = guess
				smallestGuessSize = guessSize
			}
		}
		fmt.Printf("%s", smallestGuess)

	}
}

func BinarySearchAtttack() {

}

func main() {
	NaiveAttack()
	//TODO: NaiveAttack() can be optimized. You can do a binary search over the alphabet and learn 1 byte in 12 requests.
	//TODO: BinarySearchAtttack can be optimized too.
}
