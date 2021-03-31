package database

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	oauth2gorm "src.techknowlogick.com/oauth2-gorm"
)

type DBType int8

const (
  MySQL = iota
  PostgreSQL
  SQLite
  SQLServer
)

var (
  db_type string
  db_port string
  db_host string
  db_user string
  db_password string
  db_name string
)

func loadEnv() (error) {
  if err := godotenv.Load(); err != nil {
    return err
  }

  db_type = os.Getenv("DB_TYPE")
  db_port = os.Getenv("DB_PORT")
  db_host = os.Getenv("DB_HOST")
  db_user = os.Getenv("DB_USER")
  db_password = os.Getenv("DB_PASSWORD")
  db_name = os.Getenv("DB_NAME")

  return nil
}

func GetConnectionString() (oauth2gorm.DBType, string) {
  if err := loadEnv(); err != nil {
    log.Fatal("Cannot load .env file")
    return 0, ""
  }

  connectionStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s",
			      db_host, db_port, db_user, db_name, db_password)
  
  var ret oauth2gorm.DBType
  switch db_type {
    case "postgres": {
      ret = oauth2gorm.PostgreSQL
    }

    case "mysql":
      ret = oauth2gorm.MySQL

    case "SQLite":
      ret = oauth2gorm.SQLite

    case "SQLServer":
      ret = oauth2gorm.SQLServer
  }

  return ret, connectionStr
}

type DB struct {
  SQL *gorm.DB
}

func Connect() (*DB, error) {
  if err := loadEnv(); err != nil {
    fmt.Println("Cannot open env")
    return nil, err
  }
  connectionStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s",
			      db_host, db_port, db_user, db_name, db_password)

  fmt.Println(connectionStr)
  
  db, err := gorm.Open(db_type, connectionStr)
  if err != nil {
    fmt.Println(err.Error())
    return nil, err
  }

  return &DB{SQL: db}, nil
}
