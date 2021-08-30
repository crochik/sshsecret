package cmd

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mitchellh/go-homedir"
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

	encryptCmd.Flags().StringVarP(&publicKey, "key", "k", "", "path to the public key used to encrypt the message")
	encryptCmd.Flags().StringVarP(&message, "message", "m", "", "message to be encrypted")

	encryptCmd.MarkFlagRequired("key")
}

func encrypt(cmd *cobra.Command, args []string) {
	if message == "" {
		fmt.Println("What is the message?")
		reader := bufio.NewReader(os.Stdin)
		message, _ = reader.ReadString('\n')
	}

	publicKey, err := homedir.Expand(publicKey)
	if err != nil {
		fmt.Println("Failed to expand path: "+publicKey+":", err)
		return
	}

	data, err := ioutil.ReadFile(publicKey)
	if err != nil {
		fmt.Println("Failed to load public key from "+publicKey+":", err)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		fmt.Println("Error parsing key:", err)
		return
	}

	parsedCryptoKey := pubKey.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	var encryptedBytes []byte

	switch key := pubCrypto.(type) {
	case *rsa.PublicKey:
		encryptedBytes, err = rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			key,
			[]byte(message),
			nil)

	case ed25519.PublicKey:
		// https://blog.filippo.io/using-ed25519-keys-for-encryption/
		// https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
		err = errors.New("ed25519 is not supported for encryption")

	default:
		err = errors.New("unsupported key")
	}

	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	secret := base64.StdEncoding.EncodeToString(encryptedBytes)

	fmt.Println(secret)
}
