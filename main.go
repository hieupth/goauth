package main

import (
	"errors"
	"fmt"
	"net/http"

	"goauth/handle"
	"goauth/middleware/database"
	"goauth/middleware/key"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	oauth2server "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/google/uuid"
	"src.techknowlogick.com/oauth2-gorm"
)

func main() {
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


  router.POST("/register", handle.RegisterUser)
  router.POST("/login", handle.Login)

  router.GET("/credentials", func(c *gin.Context) {
    domain := c.Request.FormValue("domain")
    if domain == "" {
      c.JSON(http.StatusBadRequest, map[string]string{"message": "Data cannot empty"})
      return
    }

    privateKey, _, err := key.RSAKeyGenerater()
    if err != nil {
      c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
      return
    }

    clientId := uuid.New().String()[:8]
    clientSecret := uuid.New().String()[:8]
    err = clientStore.Set(clientId, &models.Client{
      ID: clientId,
      Secret: clientSecret,
      Domain: domain,
    })
    if err != nil {
      fmt.Println(err.Error())
    }

    c.JSON(200, map[string]string{"CLIENT_ID": clientId, "CLIENT_SECRET": clientSecret, "PRIVATE_KEY": privateKey})
  })

  router.GET("/oauth2/login", func(c *gin.Context) {
    err := server.HandleAuthorizeRequest(c.Writer, c.Request)
    if err != nil {
      c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
      return
    }
  })
  
  router.GET("/oauth2/callback", func(c *gin.Context) {
    c.JSON(http.StatusOK, c.Request.FormValue("code"))
  })

  router.GET("/oauth2/token", func(c *gin.Context) {
    err := server.HandleTokenRequest(c.Writer, c.Request) 
    if err != nil {
      c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
      return
    }
  })

  router.GET("oauth2/testValidate", func (c *gin.Context) {
    _, err := server.ValidationBearerToken(c.Request)
    if err != nil {
      c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
      return
    }
  })
  
  router.Run()
}
