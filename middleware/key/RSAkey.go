package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func RSAKeyGenerater() (string, string, error) {
  privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Println("Generate error: ", err.Error())
    return "", "", err
  }
  publicKey := &privateKey.PublicKey

  var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey) 
  privateKeyBlock := &pem.Block{
    Type: "RSA PRIVATE KEY",
    Bytes: privateKeyBytes,
  }
  privatekeyString := pem.EncodeToMemory(privateKeyBlock)

  publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
  if err != nil {
    return "", "", err
  }
  publicKeyBlock := &pem.Block{
    Type: "PUBLIC KEY",
    Bytes: publicKeyBytes,
  }
  publickeyString := pem.EncodeToMemory(publicKeyBlock)
  
  return string(privatekeyString), string(publickeyString), nil
}

func ParseRsaPrivateKeyFromPemStr(privateKeyPem string) (*rsa.PrivateKey, error) {
  block, _ := pem.Decode([]byte(privateKeyPem))
  if block == nil {
    return nil, errors.New("failed to prase PEM block contaning the key")
  }

  privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    return nil, err
  }
  return privateKey, nil
}

func ParseRsaPublicKeyFromPemStr(publicKeyPem string) (*rsa.PublicKey, error) {
  block, _ := pem.Decode([]byte(publicKeyPem))
  if block == nil {
    return nil, errors.New("failed to prase PEM block contaning the key")
  }
  publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
  if err != nil {
    return nil, err
  }
  return publicKey, nil
}

// func EnCode(data map[string]string, publicKey *rsa.PublicKey) (string, error) {
// }
