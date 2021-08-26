package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt message",
	Long:  `Decrypt message encrypted with public key.`,
	Run:   decrypt,
}

var (
	privateKey string
	cipherText string
)

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVar(&privateKey, "key", os.Getenv("HOME")+"/.ssh/id_rsa", "path to the private key used to decripted message")
	decryptCmd.Flags().StringVar(&cipherText, "message", "", "encrypted message")
}

func decrypt(cmd *cobra.Command, args []string) {
	if cipherText == "" {
		fmt.Println("What is the message?")
		reader := bufio.NewReader(os.Stdin)
		cipherText, _ = reader.ReadString('\n')
	}

	data, err := ioutil.ReadFile(privateKey)
	if err != nil {
		fmt.Println("Failed to load public key from "+publicKey, err)
		return
	}

	bytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		fmt.Println("Error decoding encrypted message")
		return
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		fmt.Println("Failed decoding key")
		return
	}

	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		fmt.Println("Failed to parse private key", err)
		return
	}

	rsaKey := key.(*rsa.PrivateKey)

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, bytes, nil)

	if err != nil {
		fmt.Println("Failed to decrypt message", err)
		return
	}

	fmt.Println(string(decrypted))
}
