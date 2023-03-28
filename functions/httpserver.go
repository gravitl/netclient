package functions

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
)

type Network struct {
	Node   config.Node
	Server config.Server
}

func HttpServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	router := SetupRouter()
	svr := &http.Server{
		Addr:    "127.0.0.1:8090",
		Handler: router,
	}
	//	router.Run("127.0.0.1:8090")
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
	return router
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
	if err := Register(token.Token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "invalid data " + err.Error()})
		log.Println("join failed", err)
		return
	}
	c.JSON(http.StatusOK, nil)
}

func getNetwork(c *gin.Context) {
	server := config.Server{}
	network := c.Params.ByName("net")
	nodes := config.GetNodes()
	for _, node := range nodes {
		node := node
		if node.Network == network {
			server = *config.GetServer(node.Server)
			c.JSON(http.StatusOK, Network{node, server})
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
	err := Pull()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
	}
	node := config.GetNode(net)
	server := config.GetServer(node.Server)
	network := Network{
		Node:   node,
		Server: *server,
	}
	c.JSON(http.StatusOK, network)
}

func nodePeers(c *gin.Context) {
	node := config.Node{}
	if err := c.BindJSON(node); err != nil {
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
