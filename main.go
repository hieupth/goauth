package main

import (
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
  manager.MustTokenStorage(store.NewMemoryTokenStore())

  clientStore := store.NewClientStore()
  manager.MapClientStorage(clientStore)

  server := oauth2server.NewDefaultServer(manager)
  server.SetAllowGetAccessRequest(true)
  server.SetClientInfoHandler(oauth2server.ClientFormHandler)
  manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

  //setting token database
  DBType, ConnectionStr := database.GetConnectionString()
  storeConfig := oauth2gorm.NewConfig(ConnectionStr, DBType, "oauth2_token")
  tokenStore := oauth2gorm.NewStore(storeConfig, 600)
  defer tokenStore.Close()

  manager.MapTokenStorage(tokenStore)

  router := gin.Default()

  router.POST("/register", handle.RegisterUser)

  router.POST("/login", handle.Login)

  router.GET("/credentials", func(c *gin.Context) {
    var requestData struct {
      Domain string `json:"domain" form:"domain" binding:"required"`
    }
    if err := c.ShouldBindJSON(requestData); err != nil {
      c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
      return
    }

    clientId := uuid.New().String()[:8]
    clientSecret := uuid.New().String()[:8]
    err := clientStore.Set(clientId, &models.Client{
      ID: clientId,
      Secret: clientSecret,
      Domain: requestData.Domain,
    })
    if err != nil {
      fmt.Println(err.Error())
    }
    c.JSON(200, map[string]string{"CLIENT_ID": clientId, "CLIENT_SECRET": clientSecret})
  })
  
  router.Run()
}
