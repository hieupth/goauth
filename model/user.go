package model

import "time"

type User struct {
  Id int `form:"id" form:"id"`
  Name string `form:"name" json:"name" binding:"required"`
  Username string `form:"username" json:"username" binding:"required"`
  Password string `form:"password" json:"password" binding:"required"`
  Email string `form:"email" json:"email" binding:"required"`
  Created_at time.Time `form:"created_at" json:"created_at"`
}
