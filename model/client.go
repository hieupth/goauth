package model

type Client struct {
  ClientID string `json:"client_id"`
  Publickey string `json:"publickey"`
  Domain string `json:"domain"`
}
