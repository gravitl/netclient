package models

// NetworkParams defines the parameters for joining a network
type NetworkParams struct {
	ApiConn         string `json:"apiConn"`
	Key             string `json:"key"`
	Network         string `json:"network"`
	AccessKey       string `json:"accessKey"`
	Server          string `json:"server"`
	Name            string `json:"name"`
	Port            int32  `json:"port"`
	Endpoint        string `json:"enpoint"`
	IsLocal         bool   `json:"isLocal"`
	PrivateKey      string `json:"privateKey"`
	PublicKey       string `json:"publicKey"`
	MacAddress      string `json:"macAddress"`
	Password        string `json:"password"`
	Token           string `json:"token"`
	User            string `json:"user"`
	LocalRange      string `json:"localRange"`
	LocalAddress    string `json:"localAddress"`
	Address         string `json:"address"`
	Address6        string `json:"address6"`
	Interface       string `json:"interface"`
	PostUp          string `json:"postUp"`
	PostDown        string `json:"postdown"`
	PublicIpService string `json:"publicIpService"`
	IsStatic        bool   `json:"isStatic"`
	IsDnsOn         bool   `json:"isDnsOn"`
	IsIpForwarding  bool   `json:"isIpForwarding"`
	KeepAlive       int    `json:"keepAlive"`
}
