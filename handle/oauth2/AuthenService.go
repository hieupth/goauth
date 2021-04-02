package oauth2

import (
	"goauth/middleware/database"
	"goauth/middleware/key"
	"goauth/middleware/token"
	"goauth/model"
	"net/http"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func Credential(c *gin.Context) {
  domain := c.Request.FormValue("domain")
  if domain == "" {
    c.JSON(http.StatusBadRequest, map[string]string{"error": "domain pargam cannot empty"})
    return
  }

  privateKey, publicKey, err := key.RSAKeyGenerater()
  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    return
  }

  client := &model.Client{
    ClientID: uuid.New().String(),
    Publickey: publicKey,
    Domain: domain,
  }
  
  db, err := database.Connect()
  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    return
  }

  err = db.SQL.Table("client").Create(client).Error
  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    return
  }

  c.JSON(http.StatusOK, map[string]string{
    "ClientID": client.ClientID,
    "Privatekey": privateKey,
  })
}  

func Login(c *gin.Context) {
  username, password := c.Request.FormValue("username"), c.Request.FormValue("password")
  if govalidator.IsNull(username) || govalidator.IsNull(password) {
    c.JSON(http.StatusBadRequest, map[string]string{"error": "username or password pargam is empty"})
    return
  } 

  userId, err := database.ValidateUser(username, password)
  
  if err != nil {
    c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
    return
  }
  
  newToken, err := token.ServerKey.Create(userId)

  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    return 
  }

  redirect_uri := c.Request.FormValue("redirect_uri")
  if redirect_uri == "" {
    c.JSON(http.StatusOK, map[string]string{"token": newToken})
    return 
  }
  
  c.Writer.Header().Add("Authorization", "Bearer " + newToken)
  c.Redirect(302, redirect_uri)
}

func Auth(c *gin.Context) {
  auth := c.Request.Header.Get("Authorization")
  prefix := "Bearer "
  Token := ""

  if auth != "" && strings.HasPrefix(auth, prefix) {
    Token = auth[len(prefix):]
  } else {
    Token = c.Request.FormValue("access_token")
  }

  data, err := token.ServerKey.ValidationToken(Token)
  if err != nil {
    c.JSON(401, map[string]string{"error": err.Error()})
    return
  }

  c.JSON(http.StatusOK, map[string]interface{}{"data": data})
}
