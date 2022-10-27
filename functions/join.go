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
	"runtime"
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
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/models/promodels"
	"github.com/kr/pretty"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// JoinViaSso - Handles the Single Sign-On flow on the end point VPN client side
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
	socketUrl := fmt.Sprintf("wss://%s/api/oauth/node-handler", server)
	// Dial the netmaker server controller
	conn, _, err := websocket.DefaultDialer.Dial(socketUrl, nil)
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

// JoinNetwork - helps a client join a network
func JoinNetwork(flags *viper.Viper) error {
	node := models.Node{}
	n := config.Node{}
	node.Network = flags.GetString("network")
	if node.Network == "" {
		return errors.New("no network provided")
	}
	if local.HasNetwork(node.Network) {
		return errors.New("ALREADY_INSTALLED. Netclient appears to already be installed for " + node.Network + ". To re-install, please remove by executing 'sudo netclient leave -n " + node.Network + "'. Then re-run the install command.")
	}
	node.Server = flags.GetString("server")
	server, err := config.ReadServerConfig(node.Server)
	if err != nil {
		return fmt.Errorf("error reading server config %w", err)
	}
	if server == nil {
		server = &config.Server{}
	}
	///if err := config.WriteNodeConfig(node); err != nil {
	//return fmt.Errorf("error saving node config %w", err)
	//}
	node.Password = flags.GetString("password")

	if node.Password == "" {
		node.Password = logic.GenPassWord()
	}
	//check if ListenPort was set on command line
	node.ListenPort = flags.GetInt32("listenport")
	if node.ListenPort != 0 {
		node.UDPHolePunch = "no"
	}
	var trafficPubKey, trafficPrivKey, errT = box.GenerateKey(rand.Reader) // generate traffic keys
	if errT != nil {
		return fmt.Errorf("error generating traffic keys %w", errT)
	}
	//handle traffic keys
	n.TrafficPrivateKey = trafficPrivKey
	trafficPubKeyBytes, err := ncutils.ConvertKeyToBytes(trafficPubKey)
	if err != nil {
		return fmt.Errorf("error converting traffic key %w", err)
	} else if trafficPubKeyBytes == nil {
		return fmt.Errorf("traffic key is nil")
	}
	node.TrafficKeys.Mine = trafficPubKeyBytes
	node.TrafficKeys.Server = nil
	// == end handle keys ==
	if node.LocalAddress == "" {
		intIP, err := getPrivateAddr()
		if err == nil {
			node.LocalAddress = intIP.String()
		} else {
			logger.Log(1, "network:", node.Network, "error retrieving private address: ", err.Error())
		}
	}
	// set endpoint if blank. set to local if local net, retrieve from function if not
	node.Endpoint = flags.GetString("endpoint")
	isLocal := flags.GetBool("islocal")
	node.IsLocal = "no"
	if isLocal {
		node.IsLocal = "yes"
	}
	log.Println(node.Endpoint, node.IsLocal, node.LocalAddress)
	if node.Endpoint == "" {
		if node.IsLocal == "yes" && node.LocalAddress != "" {
			node.Endpoint = node.LocalAddress
		} else {
			node.Endpoint, err = ncutils.GetPublicIP(flags.GetString("apiconn"))
			if err != nil {
				return fmt.Errorf("error setting public ip %w", err)
			}
		}
		if err != nil || node.Endpoint == "" {

			logger.Log(0, "network:", node.Network, "error setting node.Endpoint.")
			return fmt.Errorf("error setting node.Endpoint for %s network, %w", node.Network, err)
		}
	}
	// Generate and set public/private WireGuard Keys
	if flags.GetString("privatekey") == "" {
		n.PrivateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			logger.FatalLog(err.Error())
		}
	}
	node.PublicKey = n.PrivateKey.PublicKey().String()
	// Find and set node MacAddress
	if flags.GetString("macddress") == "" {
		macs, err := ncutils.GetMacAddr()
		if err != nil || len(macs) == 0 {
			//if macaddress can't be found set to random string
			node.MacAddress = ncutils.MakeRandomString(18)
		} else {
			node.MacAddress = macs[0].String()
		}
	}
	netclient, err := config.ReadNetclientConfig()
	if err != nil {
		return fmt.Errorf("error reading netclient config %w", err)
	}
	if ncutils.IsFreeBSD() {
		node.UDPHolePunch = "no"
		netclient.FirewallInUse = models.FIREWALL_IPTABLES // nftables not supported by FreeBSD
	}
	if netclient.FirewallInUse == "" {
		if ncutils.IsNFTablesPresent() {
			netclient.FirewallInUse = models.FIREWALL_NFTABLES
		} else if ncutils.IsIPTablesPresent() {
			netclient.FirewallInUse = models.FIREWALL_IPTABLES
		} else {
			netclient.FirewallInUse = models.FIREWALL_NONE
		}
	}
	// make sure name is appropriate, if not, give blank name
	node.Name = formatName(flags.GetString("name"))
	node.OS = runtime.GOOS
	netclient.Version = ncutils.Version
	//   ---- not sure this is required node.AccessKey = cfg.AccessKey
	//not sure why this is needed ... setnode defaults should take care of this on server
	netclient.IPForwarding = true
	server.API = flags.GetString("apiconn")
	node.AccessKey = flags.GetString("accesskey")
	logger.Log(0, "joining "+node.Network+" at "+server.API)
	//pretty.Println(node)
	api := httpclient.JSONEndpoint[models.NodeGet]{
		URL:           "https://" + server.API,
		Route:         "/api/nodes/" + node.Network,
		Method:        http.MethodPost,
		Authorization: "Bearer " + node.AccessKey,
		Data:          node,
		Response:      models.NodeGet{},
	}
	response, err := api.GetJSON(models.NodeGet{})
	//pretty.Println(response)
	if err != nil {
		return fmt.Errorf("error creating node %w", err)
	}
	nodeGET := response.(models.NodeGet)
	newNode := config.ConvertNode(&nodeGET.Node)
	newNode.TrafficPrivateKey = n.TrafficPrivateKey
	newNode.PrivateKey = n.PrivateKey

	/*  not sure the point of following
	if nodeGET.Peers == nil {
		newNode.Peers = []wgtypes.PeerConfig{}
	}
	*/
	// safety check. If returned node from server is local, but not currently configured as local, set to local addr
	if node.IsLocal != "yes" && newNode.IsLocal && newNode.LocalRange.IP != nil {
		newNode.LocalAddress = newNode.LocalRange
		newNode.Endpoint = newNode.LocalAddress
	}
	if ncutils.IsFreeBSD() {
		newNode.UDPHolePunch = false
		newNode.IsStatic = true
	}
	if err := config.WriteServerConfig(&nodeGET.ServerConfig); err != nil {
		return fmt.Errorf("error wrting sever config %w", err)
	}
	if newNode.IsPending {

		logger.Log(0, "network:", newNode.Network, "node is marked as PENDING.")
		logger.Log(0, "network:", newNode.Network, "awaiting approval from Admin before configuring WireGuard.")
	}
	logger.Log(1, "network:", node.Network, "node created on remote server...updating configs")
	err = config.ModPort(newNode)
	if err != nil {
		return fmt.Errorf("modPort error %w", err)
	}
	informPortChange(newNode)
	pretty.Println("saving new node")
	pretty.Println(newNode)
	if err := config.WriteNodeConfig(*newNode); err != nil {
		return fmt.Errorf("error saving node config %w", err)
	}
	// attempt to make backup
	if err = config.SaveBackups(node.Network); err != nil {
		logger.Log(0, "network:", node.Network, "failed to make backup, node will not auto restore if config is corrupted")
	}

	local.SetNetmakerDomainRoute(server.API)
	logger.Log(0, "starting wireguard")
	err = wireguard.InitWireguard(newNode, nodeGET.Peers[:])
	if err != nil {
		return fmt.Errorf("error initializing wireguard %w", err)
	}
	if server.Broker == "" {
		return errors.New("did not receive broker address from registration")
	}
	if netclient.DaemonInstalled {
		if err := daemon.Restart(); err != nil {
			logger.Log(3, "daemon restart failed:", err.Error())
			if err := daemon.Start(); err != nil {
				return fmt.Errorf("error restarting deamon %w", err)
			}
		}
	}
	netclient.Save()
	return nil
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
		if err != nil {
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
