package generater

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
)

func KeyGenerater() (error) {
  privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Println("Generate error: ", err.Error())
    return err
  }
  publicKey := &privateKey.PublicKey

  var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey) 
  privateKeyBlock := &pem.Block{
    Type: "RSA PRIVATE KEY",
    Bytes: privateKeyBytes,
  }
  privateKeyPem, err := os.Create("privatekey.pem")
  if err != nil {
    fmt.Println("error when create privateKey.Pem: ", err.Error())
    return err
  }
  err = pem.Encode(privateKeyPem, privateKeyBlock)
  if err != nil {
    fmt.Println("error encode privateKey.Pem: ", err.Error())
    return err
  }

  publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
  if err != nil {
    fmt.Println("error when dumping publicKey: ", err.Error())
    return err
  }
  publicKeyBlock := &pem.Block{
    Type: "PUBLIC KEY",
    Bytes: publicKeyBytes,
  }
  publicPem, err := os.Create("public.pem")
  if err != nil {
    fmt.Println("error when create publicPem: ", err.Error())
    return err
  }
  err = pem.Encode(publicPem, publicKeyBlock)
  if (err != nil) {
    fmt.Println("error when encode publicKey: ", err.Error())
    return err
  }
  
  return nil
}
