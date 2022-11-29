package functions

import (
	"crypto/rand"
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
	"time"

	"github.com/devilcove/httpclient"
	"github.com/gorilla/websocket"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/local"
	ncmodels "github.com/gravitl/netclient/models"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/models/promodels"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Join joins a netmaker network
func Join(nwParams *ncmodels.NetworkParams) (*config.Node, *config.Server, error) {
	//config.ParseJoinFlags(cmd)
	fmt.Println("join called")
	if nwParams.Server != "" {
		//SSO sign on
		if nwParams.Network == "" {
			logger.Log(0, "no network provided")
		}
		log.Println()
		ssoAccessToken, err := JoinViaSSo(nwParams)
		if err != nil {
			logger.Log(0, "Join failed:", err.Error())
			return nil, nil, err
		}
		log.Println("token from SSo")
		if ssoAccessToken == nil {
			fmt.Println("login failed")
			return nil, nil, err
		}
		nwParams.Network = ssoAccessToken.ClientConfig.Network
		nwParams.AccessKey = ssoAccessToken.ClientConfig.Key
		nwParams.LocalRange = ssoAccessToken.ClientConfig.LocalRange
		nwParams.ApiConn = ssoAccessToken.APIConnString
	}
	token := nwParams.Token
	if token != "" {
		logger.Log(3, "parsing token flag")
		accessToken, err := config.ParseAccessToken(token)
		if err != nil {
			logger.Log(0, "failed to parse access token", token, err.Error())
			return nil, nil, err
		}
		nwParams.Network = accessToken.ClientConfig.Network
		nwParams.AccessKey = accessToken.ClientConfig.Key
		nwParams.LocalRange = accessToken.ClientConfig.LocalRange
		nwParams.ApiConn = accessToken.APIConnString

	}
	logger.Log(1, "Joining network: ", nwParams.Network)
	node, newServer, err := JoinNetwork(nwParams)
	if err != nil {
		//if !strings.Contains(err.Error(), "ALREADY_INSTALLED") {
		//logger.Log(0, "error installing: ", err.Error())
		//err = WipeLocal(node)
		//if err != nil {
		//logger.FatalLog("error removing artifacts: ", err.Error())
		//}
		//}
		//if strings.Contains(err.Error(), "ALREADY_INSTALLED") {
		logger.FatalLog(err.Error())
	}
	time.Sleep(time.Minute * 3)
	//save new configurations
	config.Nodes[node.Network] = *node
	//use existing server config if it exists, else use new server data
	server := config.GetServer(node.Server)
	if server == nil {
		server = newServer
		server.Nodes = make(map[string]bool)
	}
	nodes := server.Nodes
	nodes[node.Network] = true
	server.Nodes = nodes
	if err := config.SaveServer(node.Server, *server); err != nil {
		logger.Log(0, "failed to save server", err.Error())
	}
	config.Servers[node.Network] = *server
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saveing netclient config", err.Error())
	}
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "error saveing netclient config", err.Error())
	}
	logger.Log(1, "joined", node.Network)
	if config.Netclient.DaemonInstalled {
		if err := daemon.Restart(); err != nil {
			logger.Log(3, "daemon restart failed:", err.Error())
			if err := daemon.Start(); err != nil {
				logger.FatalLog("error restarting deamon", err.Error())
			}
		}
	}

	return node, newServer, err
}

// JoinViaSSo - Handles the Single Sign-On flow on the end point VPN client side
// Contacts the server provided by the user (and thus specified in cfg.SsoServer)
// get the URL to authenticate with a provider and shows the user the URL.
// Then waits for user to authenticate with the URL.
// Upon user successful auth flow finished - server should return access token to the requested network
// Otherwise the error message is sent which can be displayed to the user
func JoinViaSSo(nwParams *ncmodels.NetworkParams) (*models.AccessToken, error) {
	var accessToken *models.AccessToken
	// User must tell us which network he is joining
	network := nwParams.Network
	server := nwParams.Server
	user := nwParams.User
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
	if nwParams.MacAddress != "" {
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

// JoinNetwork - helps a client join a network
func JoinNetwork(nwParams *ncmodels.NetworkParams) (*config.Node, *config.Server, error) {
	netclient := &config.Netclient
	nodeForServer := models.Node{} //node to send to server
	clientNode := &config.Node{}   //local node
	nodeForServer.Network = nwParams.Network
	if nodeForServer.Network == "" {
		return nil, nil, errors.New("no network provided")
	}
	if _, ok := config.Nodes[nodeForServer.Network]; ok {
		return nil, nil, errors.New("ALREADY_INSTALLED. Netclient appears to already be installed for " + nodeForServer.Network + ". To re-install, please remove by executing 'sudo netclient leave -n " + nodeForServer.Network + "'. Then re-run the install command.")
	}
	nodeForServer.Server = nwParams.Server
	// figure out how to handle commmad line passwords
	//  TOOD !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
	//node.Password = nwParams.Password
	//if node.Password == "" {
	nodeForServer.Password = netclient.HostPass
	nodeForServer.HostID = netclient.HostID
	//}
	//check if ListenPort was set on command line
	nodeForServer.UDPHolePunch = "yes" // set default
	nodeForServer.ListenPort = nwParams.Port
	if nodeForServer.ListenPort != 0 {
		nodeForServer.UDPHolePunch = "no"
	}
	var trafficPubKey, trafficPrivKey, errT = box.GenerateKey(rand.Reader) // generate traffic keys
	if errT != nil {
		return nil, nil, fmt.Errorf("error generating traffic keys %w", errT)
	}
	//handle traffic keys
	trafficPrivKeyBytes, err := ncutils.ConvertKeyToBytes(trafficPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error converting traffic key %w", err)
	} else if trafficPrivKeyBytes == nil {
		return nil, nil, fmt.Errorf("traffic key is nil")
	}
	clientNode.TrafficPrivateKey = trafficPrivKeyBytes
	trafficPubKeyBytes, err := ncutils.ConvertKeyToBytes(trafficPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error converting traffic key %w", err)
	} else if trafficPubKeyBytes == nil {
		return nil, nil, fmt.Errorf("traffic key is nil")
	}
	nodeForServer.TrafficKeys.Mine = trafficPubKeyBytes
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
	// set endpoint if blank. set to local if local net, retrieve from function if not
	nodeForServer.Endpoint = nwParams.Endpoint
	isLocal := nwParams.IsLocal
	nodeForServer.IsLocal = "no"
	if isLocal {
		nodeForServer.IsLocal = "yes"
	}
	if nodeForServer.Endpoint == "" {
		if nodeForServer.IsLocal == "yes" && nodeForServer.LocalAddress != "" {
			nodeForServer.Endpoint = nodeForServer.LocalAddress
		} else {
			nodeForServer.Endpoint, err = ncutils.GetPublicIP(nwParams.ApiConn)
			if err != nil {
				return nil, nil, fmt.Errorf("error setting public ip %w", err)
			}
		}
		if err != nil || nodeForServer.Endpoint == "" {

			logger.Log(0, "network:", nodeForServer.Network, "error setting node.Endpoint.")
			return nil, nil, fmt.Errorf("error setting node.Endpoint for %s network, %w", nodeForServer.Network, err)
		}
	}
	// Generate and set public/private WireGuard Keys
	if nwParams.PrivateKey == "" {
		clientNode.PrivateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			logger.FatalLog(err.Error())
		}
	}
	nodeForServer.PublicKey = clientNode.PrivateKey.PublicKey().String()
	// Find and set node MacAddress
	if nwParams.MacAddress == "" {
		macs, err := ncutils.GetMacAddr()
		if err != nil || len(macs) == 0 {
			//if macaddress can't be found set to random string
			nodeForServer.MacAddress = ncutils.MakeRandomString(18)
		} else {
			nodeForServer.MacAddress = macs[0].String()
		}
	}
	/////ToDO !!!!!!!!!!!!!!!!!!!!!!!
	// what is this check for
	if err != nil {
		return nil, nil, fmt.Errorf("error reading netclient config %w", err)
	}
	if ncutils.IsFreeBSD() {
		nodeForServer.UDPHolePunch = "no"
		config.Netclient.FirewallInUse = models.FIREWALL_IPTABLES // nftables not supported by FreeBSD
	}
	if config.Netclient.FirewallInUse == "" {
		if ncutils.IsNFTablesPresent() {
			config.Netclient.FirewallInUse = models.FIREWALL_NFTABLES
		} else if ncutils.IsIPTablesPresent() {
			config.Netclient.FirewallInUse = models.FIREWALL_IPTABLES
		} else {
			config.Netclient.FirewallInUse = models.FIREWALL_NONE
		}
	}
	// make sure name is appropriate, if not, give blank name
	nodeForServer.Name = formatName(nwParams.Name)
	//config.Netclient.OS = runtime.GOOS
	//config.Netclient.Version = ncutils.Version
	//   ---- not sure this is required node.AccessKey = cfg.AccessKey
	//not sure why this is needed ... setnode defaults should take care of this on server
	//config.Netclient.IPForwarding = true
	url := nwParams.ApiConn
	nodeForServer.AccessKey = nwParams.AccessKey
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
	response, err := api.GetJSON(models.NodeGet{}, models.ErrorResponse{})
	if err != nil {
		if err == httpclient.ErrStatus {
			logger.Log(1, "error joining network", strconv.Itoa(response.(models.ErrorResponse).Code), response.(models.ErrorResponse).Message)
		}
		return nil, nil, fmt.Errorf("error creating node %w", err)
	}
	nodeGET := response.(models.NodeGet)
	newNode := config.ConvertNode(&nodeGET.Node)
	newNode.TrafficPrivateKey = clientNode.TrafficPrivateKey
	newNode.PrivateKey = clientNode.PrivateKey
	newNode.Connected = true
	// safety check. If returned node from server is local, but not currently configured as local, set to local addr
	if nodeForServer.IsLocal != "yes" && newNode.IsLocal && newNode.LocalRange.IP != nil {
		newNode.LocalAddress = newNode.LocalRange
		newNode.EndpointIP = net.ParseIP(newNode.LocalAddress.IP.String())
	}
	if ncutils.IsFreeBSD() {
		newNode.UDPHolePunch = false
		newNode.IsStatic = true
	}
	server := config.ConvertServerCfg(&nodeGET.ServerConfig)
	if newNode.IsPending {
		logger.Log(0, "network:", newNode.Network, "node is marked as PENDING.")
		logger.Log(0, "network:", newNode.Network, "awaiting approval from Admin before configuring WireGuard.")
	}
	logger.Log(1, "network:", nodeForServer.Network, "node created on remote server...updating configs")
	err = config.ModPort(newNode)
	if err != nil {
		return nil, nil, fmt.Errorf("modPort error %w", err)
	}
	informPortChange(newNode)
	config.Nodes[newNode.Network] = *newNode
	local.SetNetmakerDomainRoute(server.API)
	logger.Log(0, "starting wireguard")
	nc := wireguard.NewNCIface(newNode)
	err = nc.Create()
	if err != nil {
		return newNode, nil, fmt.Errorf("error creating interface %w", err)
	}
	if err = wireguard.Configure(newNode.PrivateKey.String(), newNode.ListenPort, newNode); err != nil {
		return newNode, nil, fmt.Errorf("error initializing wireguard %w", err)
	}
	if len(nodeGET.Peers) > 0 {
		if err = wireguard.ApplyPeers(newNode, nodeGET.Peers[:]); err != nil {
			logger.Log(0, "failed to apply peers", err.Error())
		}
	}
	return newNode, server, err
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

// format name appropriately. Set to blank on failure
func formatName(name string) string {
	// Logic to properly format name
	node := models.Node{}
	node.Name = name
	if !node.NameInNodeCharSet() {
		node.Name = ncutils.DNSFormatString(node.Name)
	}
	if len(node.Name) > models.MAX_NAME_LENGTH {
		node.Name = ncutils.ShortenString(node.Name, models.MAX_NAME_LENGTH)
	}
	if !node.NameInNodeCharSet() || len(node.Name) > models.MAX_NAME_LENGTH {
		logger.Log(1, "network:", node.Network, "could not properly format name: "+node.Name)
		logger.Log(1, "network:", node.Network, "setting name to blank")
		node.Name = ""
	}
	return node.Name
}
