package token

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	// "github.com/gin-gonic/gin"
)

type JWT struct {
  privateKey []byte
  publicKey []byte
}

func NewJWT(privateKey []byte, publicKey []byte) JWT {
  return JWT{
    privateKey: privateKey,
    publicKey: publicKey,
  }
}

var ServerKey JWT

func (j JWT) Create(content interface{}) (string, error) {
  // key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
  key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
  if err != nil {
    return "", fmt.Errorf("create: parse key: %w", err)
  }

  claims := make(jwt.MapClaims)
  claims["dat"] = content
  claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
  claims["iat"] = time.Now()
  
  token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
  if err != nil {
    return "", fmt.Errorf("create: sign token: %w", err)
  }
  
  return token, nil
}

func (j JWT) ValidationToken(token string) (interface{}, error) {
  key, err := jwt.ParseRSAPublicKeyFromPEM(ServerKey.publicKey)
  if err != nil {
    return "", fmt.Errorf("validate: parse key: %w", err)
  }

  tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
    if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
      return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
    }
    return key, nil
  })
  if err != nil {
    return nil, fmt.Errorf("validate: %w", err)
  }
  
  claims, ok := tok.Claims.(jwt.MapClaims)
  if !ok || !tok.Valid {
    return nil, fmt.Errorf("validate: invalid")
  }

  return claims["dat"], nil
}
