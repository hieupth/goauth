package handle

import (
	"fmt"
	"goauth/middleware/database"
	"goauth/model"
	"goauth/middleware/jwt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func santize(data *string) {
  var temp string = *data
  temp = html.EscapeString(strings.TrimSpace(temp))
  data = &temp
}

func hash(password string) (string, error) {
  bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
  return string(bytes), err
}

func checkHashPassword(hashedPassword, password string) (error) {
  return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func RegisterUser(c *gin.Context) {
  var requestData model.User

  if err := c.ShouldBindJSON(&requestData); err != nil {
    c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
    return 
  }

  if govalidator.IsNull(requestData.Username) || govalidator.IsNull(requestData.Password) || govalidator.IsNull(requestData.Name) {
    c.JSON(http.StatusBadRequest, map[string]string{"message": "Data cannot empty"})
    return
  }

  if govalidator.IsNull(requestData.Email) || !govalidator.IsEmail(requestData.Email) {
    c.JSON(http.StatusBadRequest, map[string]string{"message": "Email is invalid"})
    return
  }

  var err error
  requestData.Password, err = hash(requestData.Password)
  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"message": "Cannot hash password: " + err.Error()})
    return 
  }
  requestData.Created_at = time.Now()

  db, err := database.Connect()
  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"message": "Cannot connect to database"})
    return
  }
  defer db.SQL.Close()
  
  err = db.SQL.Table("users").Create(&requestData).Error
  if err != nil {
    c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
    return
  }
  fmt.Println("Create new users: ", requestData)
  c.JSON(http.StatusOK, map[string]string{"message": "Create new user succesful"})
}

func Login(c *gin.Context) {
  var loginRequest struct {
    Username string `json:"username" form:"username" binding:"required"`
    Password string `json:"password" form:"password" binding:"required"`
  }

  if err := c.ShouldBindJSON(&loginRequest); err != nil {
    c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
    return
  }

  db, err := database.Connect()
  if err != nil {
    c.JSON(http.StatusInternalServerError, err.Error())
    return
  }
  
  var databaseUser model.User
  err = db.SQL.Table("users").Find(&databaseUser, "username = ?", loginRequest.Username).Error
  if err != nil {
    c.JSON(http.StatusNonAuthoritativeInfo, map[string]string{"message": err.Error()})
    return 
  }

  if err = checkHashPassword(databaseUser.Password, loginRequest.Password); err != nil {
    c.JSON(http.StatusNotAcceptable, map[string]string{"message": err.Error()})
    return 
  }

  token, err := jwt.Create(databaseUser) 
  if err != nil {
    c.JSON(http.StatusInternalServerError, err.Error())
    return 
  }
  
  c.JSON(http.StatusAccepted, map[string]string{"token": token})
}
