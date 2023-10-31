package functions

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

type Network struct {
	Node   config.Node
	Server config.Server
}

const DefaultHttpServerPort = "18095"
const DefaultHttpServerAddr = "127.0.0.1"

func HttpServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if config.Netclient().DisableGUIServer {
		return
	}
	port := DefaultHttpServerPort
	if runtime.GOOS != "windows" {
		p, err := ncutils.GetFreeTCPPort()
		if err != nil {
			logger.Log(0, "failed to get free port", err.Error())
			logger.Log(0, "unable to start http server", "exiting")
			logger.Log(0, "netclient-gui will not be available")
			return
		}
		port = p
	}
	config.SetGUI(DefaultHttpServerAddr, port)
	config.WriteGUIConfig()

	router := SetupRouter()
	svr := &http.Server{
		Addr:    config.GetGUI().Address + ":" + config.GetGUI().Port,
		Handler: router,
	}
	logger.Log(3, "starting http server on port ", port)
	go func() {
		if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log(0, "https server err", err.Error())
		}
	}()
	<-ctx.Done()
	logger.Log(3, "shutting down http server")
	if err := svr.Shutdown(ctx); err != nil {
		logger.Log(0, "http server shutdown", err.Error())
	}
}

// SetupRoute - sets routes for http server
func SetupRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/status", status)
	router.POST("/register", register)
	router.GET("/network/:net", getNetwork)
	router.GET("/allnetworks", getAllNetworks)
	router.GET("/netclient", getNetclient)
	router.POST("/connect/:net", connect)
	router.POST("/leave/:net", leave)
	router.GET("/servers", servers)
	router.POST("/uninstall", uninstall)
	router.GET("/pull/:net", pull)
	router.POST("nodepeers", nodePeers)
	router.POST("/join", join)
	router.POST("/sso", sso)
	return router
}

func status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func register(c *gin.Context) {
	var token struct {
		Token string
	}
	err := json.NewDecoder(c.Request.Body).Decode(&token)
	if err != nil {
		//if err := c.BindJSON(&token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid data " + err.Error()})
		log.Println("bind error ", err)
		return
	}
	if err := Register(token.Token, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "invalid data " + err.Error()})
		log.Println("join failed", err)
		return
	}

	c.JSON(http.StatusOK, nil)

	go func() {
		time.Sleep(3 * time.Second)
		if err := daemon.Restart(); err != nil {
			logger.Log(3, "daemon restart failed:", err.Error())
		}
	}()
}

func getNetwork(c *gin.Context) {
	network := c.Params.ByName("net")
	nodes := config.GetNodes()
	for _, node := range nodes {
		node := node
		if node.Network == network {
			server := config.GetServer(node.Server)
			if server == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "server config not found"})
				return
			}
			c.JSON(http.StatusOK, Network{node, *server})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "unknown network"})
}

func getAllNetworks(c *gin.Context) {
	configs := []Network{}
	nodes := config.GetNodes()
	for _, node := range nodes {
		node := node
		server := config.GetServer(node.Server)
		if server == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "server config not found"})
			return
		}
		configs = append(configs, Network{node, *server})
	}
	c.JSON(http.StatusOK, configs)
}

func getNetclient(c *gin.Context) {
	conf, err := config.ReadNetclientConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to read netclient config"})
		return
	}
	c.JSON(http.StatusOK, conf)
}

func connect(c *gin.Context) {
	var connect struct {
		Connect bool
	}
	net := c.Params.ByName("net")
	if err := json.NewDecoder(c.Request.Body).Decode(&connect); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "unable to read request"})
		return
	}
	if connect.Connect {
		if err := Connect(net); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
	} else {
		if err := Disconnect(net); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
	}
	c.JSON(http.StatusOK, nil)
}

func leave(c *gin.Context) {
	net := c.Params.ByName("net")
	errs, err := LeaveNetwork(net, true)
	if err == nil {
		c.JSON(http.StatusOK, nil)
		return
	}
	builder := strings.Builder{}
	for _, msg := range errs {
		builder.WriteString(msg.Error() + " ")
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": builder.String()})
}

func servers(c *gin.Context) {
	var servers struct {
		Name []string
	}
	for name := range config.Servers {
		name := name
		servers.Name = append(servers.Name, name)
	}
	c.JSON(http.StatusOK, servers)
}

func uninstall(c *gin.Context) {
	errs, err := Uninstall()
	if err == nil {
		c.JSON(http.StatusOK, nil)
		return
	}
	builder := strings.Builder{}
	for _, msg := range errs {
		builder.WriteString(msg.Error() + " ")
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": builder.String()})
}

func pull(c *gin.Context) {
	net := c.Params.ByName("net")
	_, err := Pull(true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
	}
	node := config.GetNode(net)
	server := config.GetServer(node.Server)
	if server == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "server config not found"})
		return
	}
	network := Network{
		Node:   node,
		Server: *server,
	}
	c.JSON(http.StatusOK, network)
}

func nodePeers(c *gin.Context) {
	node := config.Node{}
	if err := c.BindJSON(&node); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not parse request" + err.Error()})
		return
	}
	peers, err := GetNodePeers(node)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	c.JSON(http.StatusOK, peers)
}

func join(c *gin.Context) {
	joinReq := RegisterSSO{}
	if err := c.BindJSON(&joinReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not parse request" + err.Error()})
		return
	}
	if err := RegisterWithSSO(&joinReq, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	c.JSON(http.StatusOK, nil)
}

func sso(c *gin.Context) {
	registerData := RegisterSSO{}
	if err := c.BindJSON(&registerData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not parse request" + err.Error()})
		return
	}
	socketUrl := fmt.Sprintf("wss://%s/api/v1/auth-register/host", registerData.API)
	// Dial the netmaker server controller
	conn, _, err := websocket.DefaultDialer.Dial(socketUrl, nil)
	if err != nil {
		logger.Log(0, fmt.Sprintf("error connecting to %s : %s", registerData.API, err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	host := hostForSSO()
	request := models.RegisterMsg{
		RegisterHost: host,
		User:         registerData.User,
		Password:     registerData.Pass,
		Network:      registerData.Network,
		JoinAll:      registerData.AllNetworks,
	}
	registerData.Pass = ""
	defer conn.Close()
	reqData, err := json.Marshal(&request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	if err := conn.WriteMessage(websocket.TextMessage, reqData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if msgType < 0 {
				logger.Log(1, "received close message from server")
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			logger.Log(0, "read:", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if msgType == websocket.CloseMessage {
			logger.Log(1, "received close message from server")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "websocket closed"})
			return
		}
		if strings.Contains(string(msg), "oauth/register") { // TODO: maybe send to channel for GUI in future?
			c.JSON(http.StatusOK, gin.H{"authendpoint": string(msg)})
			return
		}
	}
}

func hostForSSO() models.Host {
	host := config.Netclient()
	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else {
		// just in case getInterfaces() returned nil, nil
		if ip != nil {
			host.Interfaces = *ip
		}
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else if defaultInterface != ncutils.GetInterfaceName() {
		host.DefaultInterface = defaultInterface
	}
	return host.Host
}
