package main

import (
	"errors"
	"fmt"
	"net/http"

	"goauth/handle"
	"goauth/middleware/database"

	// "goauth/middleware/generater"

	// "github.com/google/uuid"

	"github.com/gin-gonic/gin"
	// "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/google/uuid"

	// "github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"

	oauth2server "github.com/go-oauth2/oauth2/v4/server"
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

  router.GET("/login/oauth2/token", func(c *gin.Context) {
    err := server.HandleTokenRequest(c.Writer, c.Request) 
    if err != nil {
      c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
      return
    }
  })

  router.POST("/register", handle.RegisterUser)
  router.POST("/login", handle.Login)


  router.GET("/login/oauth2/authorize", func(c *gin.Context) {
    err := server.HandleAuthorizeRequest(c.Writer, c.Request)
    if err != nil {
      c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
      return
    }
  })
  
  router.GET("/login/oauth2/callback", func(c *gin.Context) {
    c.JSON(http.StatusOK, c.Request.FormValue("code"))
  })

  router.GET("/credentials", func(c *gin.Context) {
    domain := c.Request.FormValue("domain")
    if domain == "" {
      c.JSON(http.StatusBadRequest, map[string]string{"message": "Data cannot empty"})
      return
    }

    clientId := uuid.New().String()[:8]
    clientSecret := uuid.New().String()[:8]
    err := clientStore.Set(clientId, &models.Client{
      ID: clientId,
      Secret: clientSecret,
      Domain: domain,
    })
    if err != nil {
      fmt.Println(err.Error())
    }
    c.JSON(200, map[string]string{"CLIENT_ID": clientId, "CLIENT_SECRET": clientSecret})
  })
  
  router.Run()
}
