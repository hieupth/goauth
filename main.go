package main

import (
	// "bytes"
	"errors"
	"net/http"
	"os"

	"goauth/handle"
	"goauth/handle/oauth2"
	"goauth/middleware/database"
	"goauth/middleware/token"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"

	// "github.com/go-oauth2/oauth2/v4/models"
	oauth2server "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"src.techknowlogick.com/oauth2-gorm"
)

func main() {
  serverPrivateKey, err := os.ReadFile("ServerRSAKey/privatekey.pem")
  if err != nil {
    panic(err)
  }

  serverPublicKey, err := os.ReadFile("ServerRSAKey/publickey.pem")
  if err != nil {
    panic(err)
  }
  
  token.ServerKey = token.NewJWT(serverPrivateKey, serverPublicKey)

  manager := manage.NewDefaultManager()
  manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
  manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

  clientStore := store.NewClientStore()
  manager.MapClientStorage(clientStore)

  server := oauth2server.NewDefaultServer(manager)
  server.SetAllowGetAccessRequest(true)
  server.SetUserAuthorizationHandler(handle.GetUserId)
  server.Config.AllowGetAccessRequest = true
  server.Config.ForcePKCE = false
  server.SetClientInfoHandler(func(r *http.Request) (string, string, error) {
    clientId, clientSerect := r.FormValue("client_id"), r.FormValue("client_serect")
    if clientId == "" || clientSerect == "" {
      return "", "", errors.New("Data cannot empty")
    }
    return clientId, clientSerect, nil
  })

  //setting token database
  DBType, ConnectionStr := database.GetConnectionString()
  storeConfig := oauth2gorm.NewConfig(ConnectionStr, DBType, "oauth2_token")
  tokenStore := oauth2gorm.NewStore(storeConfig, 600)
  defer tokenStore.Close()

  // manager.MustTokenStorage(store.NewMemoryTokenStore())
  manager.MapTokenStorage(tokenStore)

  router := gin.Default()

  router.GET("/login")
  router.GET("/oauth2/login", oauth2.Login)
  router.GET("/oauth2/credential", oauth2.Credential)
  router.GET("/oauth2/auth", oauth2.Auth)
  router.GET("/test", func(c *gin.Context) {
    token := c.Request.Header.Get("Authorization")
    c.JSON(http.StatusOK, token)
  })
  
  router.Run()
}
