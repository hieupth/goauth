package jwt

import (
	// "fmt"
	"errors"
	"goauth/model"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func loadSerectKey() (string, error) {
  var jwtSerectKey string 
  err := godotenv.Load()
  if err != nil {
    return "", err
  }
  jwtSerectKey = os.Getenv("JWT_SERECT")
  return jwtSerectKey, nil
}

func Create(data model.User) (string, error) {
  jwtSerectKey, err := loadSerectKey()
  if err != nil {
    return "", nil
  }
  claims := jwt.MapClaims{}
  claims["authorized"] = true
  claims["username"] = data.Username
  claims["uid"] = data.Id
  claims["exp"] = time.Now().Add(168 * time.Hour).Unix()
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
  return token.SignedString([]byte(jwtSerectKey))
} 

func Verify(userToken string) (error) {
  jwtSerectKey, err := loadSerectKey()
  if err != nil {
    return err
  }
  token, err := jwt.Parse(userToken, func(token *jwt.Token) (interface{}, error) {
    return []byte(jwtSerectKey), nil
  })

  if err != nil {
    return err
  }

  if token.Valid {
    return nil
  }

  return errors.New("Token is not valid")
} 

func TokenValid(c *gin.Context) error {
  if err := Verify(c.Request.Header["Authorization"][0]); err != nil {
    c.JSON(http.StatusNonAuthoritativeInfo, err.Error())
    return err
  }
  return nil
}
