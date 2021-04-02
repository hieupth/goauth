package model

type User struct {
  Id int `form:"id" form:"id"`
  Username string `form:"username" json:"username" binding:"required"`
  Password string `form:"password" json:"password" binding:"required"`
}
