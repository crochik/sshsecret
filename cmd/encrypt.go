package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypt message",
	Long:  `Encrypt some short text using the public key.`,
	Run:   encrypt,
}

var (
	publicKey string
	message   string
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVar(&publicKey, "key", "", "path to the public key used to encrypt the message")
	encryptCmd.Flags().StringVar(&message, "message", "", "message to be encrypted")

	encryptCmd.MarkFlagRequired("key")
}

func encrypt(cmd *cobra.Command, args []string) {
	if message == "" {
		fmt.Println("What is the message?")
		reader := bufio.NewReader(os.Stdin)
		message, _ = reader.ReadString('\n')
	}

	data, err := ioutil.ReadFile(publicKey)
	if err != nil {
		fmt.Println("Failed to load public key from "+publicKey, err)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		fmt.Println("Error parsing key", err)
		return
	}

	parsedCryptoKey := pubKey.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()
	pub := pubCrypto.(*rsa.PublicKey)

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		[]byte(message),
		nil)

	if err != nil {
		fmt.Println("Error encrypting message", err)
		return
	}

	secret := base64.StdEncoding.EncodeToString(encryptedBytes)

	fmt.Println(secret)
}
