package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/devilcove/httpclient"
	"github.com/gorilla/websocket"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/models/promodels"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// Join joins a netmaker network with flags specified on command line
func Join(flags *viper.Viper) error {
	//config.ParseJoinFlags(cmd)
	fmt.Println("join called")
	if flags.Get("server") != "" {
		//SSO sign on
		if flags.Get("network") == "" {
			logger.Log(0, "no network provided")
		}
		log.Println()
		ssoAccessToken, err := JoinViaSSo(flags)
		if err != nil {
			logger.Log(0, "Join failed:", err.Error())
			return err
		}
		log.Println("token from SSo")
		if ssoAccessToken == nil {
			fmt.Println("login failed")
			return errors.New("could not get SSO access token")
		}
		flags.Set("network", ssoAccessToken.ClientConfig.Network)
		flags.Set("accesskey", ssoAccessToken.ClientConfig.Key)
		flags.Set("localrange", ssoAccessToken.ClientConfig.LocalRange)
		flags.Set("apiconn", ssoAccessToken.APIConnString)
	}
	token := flags.GetString("token")
	if token != "" {
		logger.Log(3, "parsing token flag")
		accessToken, err := config.ParseAccessToken(token)
		if err != nil {
			logger.Log(0, "failed to parse access token", token, err.Error())
			return err
		}
		flags.Set("network", accessToken.ClientConfig.Network)
		flags.Set("accesskey", accessToken.ClientConfig.Key)
		flags.Set("localrange", accessToken.ClientConfig.LocalRange)
		flags.Set("apiconn", accessToken.APIConnString)
	}
	logger.Log(1, "Joining network: ", flags.GetString("network"))
	node, newServer, newHost, err := JoinNetwork(flags)
	if err != nil {
		return err
	}
	//save new configurations
	config.UpdateNodeMap(node.Network, *node)
	//use existing server config if it exists, else use new server data
	server := config.GetServer(node.Server)
	if server == nil {
		server = newServer
	}
	nodes := server.Nodes
	nodes[node.Network] = true
	server.Nodes = nodes
	if err := config.SaveServer(node.Server, *server); err != nil {
		logger.Log(0, "failed to save server", err.Error())
	}
	config.UpdateNetclient(*newHost)
	log.Println("ListenPort", newHost.ListenPort, newHost.LocalListenPort)
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saveing netclient config", err.Error())
	}
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "error saveing netclient config", err.Error())
	}
	logger.Log(1, "joined", node.Network)
	if config.Netclient().DaemonInstalled {
		if err := daemon.Restart(); err != nil {
			logger.Log(3, "daemon restart failed:", err.Error())
			if err := daemon.Start(); err != nil {
				logger.FatalLog("error restarting deamon", err.Error())
			}
		}
	}

	return nil
}

// JoinViaSSo - Handles the Single Sign-On flow on the end point VPN client side
// Contacts the server provided by the user (and thus specified in cfg.SsoServer)
// get the URL to authenticate with a provider and shows the user the URL.
// Then waits for user to authenticate with the URL.
// Upon user successful auth flow finished - server should return access token to the requested network
// Otherwise the error message is sent which can be displayed to the user
func JoinViaSSo(flags *viper.Viper) (*models.AccessToken, error) {
	var accessToken *models.AccessToken
	// User must tell us which network he is joining
	network := flags.GetString("network")
	server := flags.GetString("server")
	user := flags.GetString("user")
	if network == "" {
		return nil, errors.New("no network provided")
	}
	// Prepare a channel for interrupt
	// Channel to listen for interrupt signal to terminate gracefully
	interrupt := make(chan os.Signal, 1)
	// Notify the interrupt channel for SIGINT
	signal.Notify(interrupt, os.Interrupt)
	// Web Socket is used, construct the URL accordingly ...
	socketURL := fmt.Sprintf("wss://%s/api/oauth/node-handler", server)
	// Dial the netmaker server controller
	conn, _, err := websocket.DefaultDialer.Dial(socketURL, nil)
	if err != nil {
		logger.Log(0, fmt.Sprintf("error connecting to %s : %s", server, err.Error()))
		return nil, err
	}
	// Don't forget to close when finished
	defer conn.Close()
	// Find and set node MacAddress
	var macAddress string
	if flags.GetString("macaddress") != "" {
		macs, err := ncutils.GetMacAddr()
		if err != nil {
			//if macaddress can't be found set to random string
			macAddress = ncutils.MakeRandomString(18)
		} else {
			macAddress = macs[0].String()
		}
	}
	var loginMsg promodels.LoginMsg
	loginMsg.Mac = macAddress
	loginMsg.Network = network
	if user != "" {
		fmt.Printf("Continuing with user, %s.\nPlease input password:\n", user)
		pass, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil || string(pass) == "" {
			logger.FatalLog("no password provided, exiting")
		}
		loginMsg.User = user
		loginMsg.Password = string(pass)
		fmt.Println("attempting login...")
	}
	msgTx, err := json.Marshal(loginMsg)
	if err != nil {
		logger.Log(0, fmt.Sprintf("failed to marshal message %+v", loginMsg))
		return nil, err
	}
	err = conn.WriteMessage(websocket.TextMessage, []byte(msgTx))
	if err != nil {
		logger.FatalLog("Error during writing to websocket:", err.Error())
		return nil, err
	}
	// if user provided, server will handle authentication
	if loginMsg.User == "" {
		// We are going to get instructions on how to authenticate
		// Wait to receive something from server
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		// Print message from the netmaker controller to the user
		fmt.Printf("Please visit:\n %s \n to authenticate", string(msg))
	}
	// Now the user is authenticating and we need to block until received
	// An answer from the server.
	// Server waits ~5 min - If takes too long timeout will be triggered by the server
	done := make(chan struct{})
	defer close(done)
	// Following code will run in a separate go routine
	// it reads a message from the server which either contains 'AccessToken:' string or not
	// if not - then it contains an Error to display.
	// if yes - then AccessToken is to be used to proceed joining the network
	go func() {
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				if msgType < 0 {
					logger.Log(1, "received close message from server")
					done <- struct{}{}
					return
				}
				// Error reading a message from the server
				if !strings.Contains(err.Error(), "normal") {
					logger.Log(0, "read:", err.Error())
				}
				return
			}
			if msgType == websocket.CloseMessage {
				logger.Log(1, "received close message from server")
				done <- struct{}{}
				return
			}
			// Get the access token from the response
			if strings.Contains(string(msg), "AccessToken: ") {
				// Access was granted
				rxToken := strings.TrimPrefix(string(msg), "AccessToken: ")
				accessToken, err = config.ParseAccessToken(rxToken)
				if err != nil {
					logger.Log(0, fmt.Sprintf("failed to parse received access token %s,err=%s\n", accessToken, err.Error()))
					return
				}
				/*node.Network = accessToken.ClientConfig.Network
				node.AccessKey = accessToken.ClientConfig.Key
				node.LocalRange = config.ToIPNet(accessToken.ClientConfig.LocalRange)
				//server.Server = accesstoken.ServerConfig.Server
				server.API = accessToken.APIConnString*/
			} else {
				// Access was not granted. Display a message from the server
				logger.Log(0, "Message from server:", string(msg))
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			logger.Log(1, "finished")
			return accessToken, nil
		case <-interrupt:
			logger.Log(0, "interrupt received, closing connection")
			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				logger.Log(0, "write close:", err.Error())
				return nil, err
			}
			return accessToken, nil
		}
	}
}

// JoinNetwork - connects to netmaker server to join a network
func JoinNetwork(flags *viper.Viper) (*config.Node, *config.Server, *config.Config, error) {
	netclient := config.Netclient()
	nodeForServer := models.Node{} //node to send to server
	nodeForServer.Network = flags.GetString("network")
	if nodeForServer.Network == "" {
		return nil, nil, nil, errors.New("no network provided")
	}
	nodes := config.GetNodes()
	if _, ok := nodes[nodeForServer.Network]; ok {
		return nil, nil, nil, errors.New("ALREADY_INSTALLED. Netclient appears to already be installed for " + nodeForServer.Network + ". To re-install, please remove by executing 'sudo netclient leave -n " + nodeForServer.Network + "'. Then re-run the install command.")
	}
	nodeForServer.Version = config.Netclient().Version
	nodeForServer.Server = flags.GetString("server")
	nodeForServer.Password = netclient.HostPass
	nodeForServer.HostID = netclient.HostID
	//check if ListenPort was set on command line
	nodeForServer.UDPHolePunch = "" // set default
	nodeForServer.ListenPort = flags.GetInt32("port")
	if nodeForServer.ListenPort != 0 {
		nodeForServer.UDPHolePunch = "no"
	}
	nodeForServer.TrafficKeys.Mine = config.Netclient().TrafficKeyPublic
	nodeForServer.TrafficKeys.Server = nil
	// == end handle keys ==
	if nodeForServer.LocalAddress == "" {
		intIP, err := getPrivateAddr()
		if err == nil {
			nodeForServer.LocalAddress = intIP.String()
		} else {
			logger.Log(1, "network:", nodeForServer.Network, "error retrieving private address: ", err.Error())
		}
	}
	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else {
		// just in case getInterfaces() returned nil, nil
		if ip != nil {
			nodeForServer.Interfaces = *ip
		}
	}

	// set endpoint if blank. set to local if local net, retrieve from function if not
	nodeForServer.Endpoint = flags.GetString("endpoint")
	isLocal := flags.GetBool("islocal")
	nodeForServer.IsLocal = "no"
	if isLocal {
		nodeForServer.IsLocal = "yes"
	}
	if nodeForServer.Endpoint == "" {
		if nodeForServer.IsLocal == "yes" && nodeForServer.LocalAddress != "" {
			nodeForServer.Endpoint = nodeForServer.LocalAddress
		} else {
			nodeForServer.Endpoint, err = ncutils.GetPublicIP(flags.GetString("apiconn"))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("error setting public ip %w", err)
			}
		}
		if err != nil || nodeForServer.Endpoint == "" {
			logger.Log(0, "network:", nodeForServer.Network, "error setting node.Endpoint.")
			return nil, nil, nil, fmt.Errorf("error setting node.Endpoint for %s network, %w", nodeForServer.Network, err)
		}
	}
	nodeForServer.PublicKey = config.Netclient().PublicKey.String()
	// Find and set node MacAddress
	nodeForServer.MacAddress = config.Netclient().MacAddress.String()
	// make sure name is appropriate, if not, give blank name
	nodeForServer.Name = config.Netclient().Name
	nodeForServer.FirewallInUse = config.Netclient().FirewallInUse
	nodeForServer.OS = config.Netclient().OS
	nodeForServer.IPForwarding = config.FormatBool(config.Netclient().IPForwarding)
	url := flags.GetString("apiconn")
	nodeForServer.AccessKey = flags.GetString("accesskey")
	logger.Log(0, "joining "+nodeForServer.Network+" at "+url)
	api := httpclient.JSONEndpoint[models.NodeGet, models.ErrorResponse]{
		URL:           "https://" + url,
		Route:         "/api/nodes/" + nodeForServer.Network,
		Method:        http.MethodPost,
		Authorization: "Bearer " + nodeForServer.AccessKey,
		Headers: []httpclient.Header{
			{
				Name:  "requestfrom",
				Value: "node",
			},
		},
		Data:          nodeForServer,
		Response:      models.NodeGet{},
		ErrorResponse: models.ErrorResponse{},
	}
	response, errData, err := api.GetJSON(models.NodeGet{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(1, "error joining network", strconv.Itoa(errData.Code), errData.Message)
		}
		return nil, nil, nil, fmt.Errorf("error creating node %w", err)
	}
	nodeGET := response
	config.UpdateServerConfig(&nodeGET.ServerConfig)
	newNode, newServer, newHostConfig := config.ConvertNode(&nodeGET)
	newNode.Connected = true
	// safety check. If returned node from server is local, but not currently configured as local, set to local addr
	// TODO ----- figure out what this is really trying to do and uncomment
	//if nodeForServer.IsLocal != "yes" && newNode.IsLocal && newHostConfig.LocalRange.IP != nil {
	//newHostConfig.LocalAddress = newNode.LocalRange
	//newNode.EndpointIP = net.ParseIP(newNode.LocalAddress.IP.String())
	//}
	if newNode.IsPending {
		logger.Log(0, "network:", newNode.Network, "node is marked as PENDING.")
		logger.Log(0, "network:", newNode.Network, "awaiting approval from Admin before configuring WireGuard.")
	}
	logger.Log(1, "network:", nodeForServer.Network, "node created on remote server...updating configs")
	err = config.ModPort(newHostConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("modPort error %w", err)
	}
	config.UpdateNodeMap(newNode.Network, *newNode)
	// TODO :: why here ... should be in daemon?
	local.SetNetmakerDomainRoute(newServer.API)
	logger.Log(0, "update wireguard config")
	wireguard.AddAddresses(newNode)
	peers := newNode.Peers
	for _, node := range config.GetNodes() {
		if node.Connected {
			peers = append(peers, node.Peers...)
		}
	}
	internetGateway, err := wireguard.UpdateWgPeers(peers)
	if internetGateway != nil {
		newHostConfig.InternetGateway = *internetGateway
	}
	return newNode, newServer, newHostConfig, err
}

func getPrivateAddr() (net.IPNet, error) {
	local := net.IPNet{}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()

		localAddr := conn.LocalAddr().(*net.UDPAddr)
		local = config.ToIPNet(localAddr.String())
	}
	if local.IP == nil {
		local, err = getPrivateAddrBackup()
	}

	if local.IP == nil {
		err = errors.New("could not find local ip")
	}

	return local, err
}

func getPrivateAddrBackup() (net.IPNet, error) {
	address := net.IPNet{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return address, err
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		local, err := i.Addrs()
		if err != nil || len(local) == 0 {
			continue
		}
		return config.ToIPNet(local[0].String()), nil
	}
	err = errors.New("local ip address not found")
	return address, err
}
