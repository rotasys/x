package x

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPublicKeyFromFile(file string) (interface{}, error) {
	bts, err := readInPem(file)
	if err != nil {
		return nil, err
	}

	key, err := parsePublicKey(bts)

	return key, err
}

func readInPem(path string) ([]byte, error) {
	pemFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pemfileinfo, _ := pemFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(pemFile)
	_, err = buffer.Read(pembytes)
	return pembytes, nil
	//data, _ := pem.Decode([]byte(pembytes))
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa, nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}
