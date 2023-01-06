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
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/models/promodels"
	"github.com/kr/pretty"
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
	node, server, err := JoinNetwork(flags)
	if err != nil {
		return err
	}
	log.Println("server response to join")
	pretty.Println(node, server)
	//save new configurations
	config.UpdateNodeMap(node.Network, *node)
	config.UpdateServer(node.Server, *server)
	if err := config.SaveServer(node.Server, *server); err != nil {
		logger.Log(0, "failed to save server", err.Error())
	}
	if err := config.WriteNetclientConfig(); err != nil {
		logger.Log(0, "error saving netclient config", err.Error())
	}
	if err := config.WriteNodeConfig(); err != nil {
		logger.Log(0, "error saving node map", err.Error())
	}
	if err := wireguard.WriteWgConfig(config.Netclient(), config.GetNodes()); err != nil {
		logger.Log(0, "error saving wireguard conf", err.Error())
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
		var pass string
		fmt.Printf("Continuing with user, %s.\n", user)
		if flags.GetBool("readPassFromStdIn") {
			fmt.Printf("Please input password:\n")
			passBytes, err := term.ReadPassword(int(syscall.Stdin))
			pass = string(passBytes)
			if err != nil || string(pass) == "" {
				logger.FatalLog("no password provided, exiting")
			}
		} else {
			pass = flags.GetString("pass")
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
func JoinNetwork(flags *viper.Viper) (*config.Node, *config.Server, error) {
	if flags.GetString("network") == "" {
		return nil, nil, errors.New("no network provided")
	}
	host := config.Netclient()
	node := config.GetNode(flags.GetString("network"))
	node.Network = flags.GetString("network")
	nodes := config.GetNodes()
	if _, ok := nodes[node.Network]; ok {
		return nil, nil, errors.New("ALREADY_INSTALLED. Netclient appears to already be installed for " + node.Network + ". To re-install, please remove by executing 'sudo netclient leave -n " + node.Network + "'. Then re-run the install command.")
	}
	node.Server = flags.GetString("server")
	node.HostID = host.ID
	node.Connected = true
	host.ProxyEnabled = flags.GetBool("proxy")
	// == end handle keys ==
	if host.LocalAddress.IP == nil {
		intIP, err := getPrivateAddr()
		if err == nil {
			host.LocalAddress = intIP
		} else {
			logger.Log(1, "network:", node.Network, "error retrieving private address: ", err.Error())
		}
	}
	ip, err := getInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else {
		// just in case getInterfaces() returned nil, nil
		if ip != nil {
			host.Interfaces = *ip
		}
	}

	// set endpoint if blank. set to local if local net, retrieve from function if not
	host.EndpointIP = net.ParseIP(flags.GetString("endpoint"))
	isLocal := flags.GetBool("islocal")
	node.IsLocal = false
	if isLocal {
		node.IsLocal = true
	}
	if host.EndpointIP == nil {
		if node.IsLocal && host.LocalAddress.IP != nil {
			host.EndpointIP = host.LocalAddress.IP
		} else {
			ip, err := ncutils.GetPublicIP(flags.GetString("apiconn"))
			host.EndpointIP = net.ParseIP(ip)
			if err != nil {
				return nil, nil, fmt.Errorf("error setting public ip %w", err)
			}
		}
		if host.EndpointIP == nil {
			logger.Log(0, "network:", node.Network, "error setting node.Endpoint.")
			return nil, nil, fmt.Errorf("error setting node.Endpoint for %s network, %w", node.Network, err)
		}
	}
	// make sure name is appropriate, if not, give blank name
	url := flags.GetString("apiconn")
	serverHost, serverNode := config.Convert(host, &node)
	joinData := models.JoinData{
		Host: serverHost,
		Node: serverNode,
		Key:  flags.GetString("accesskey"),
	}
	joinData.Key = flags.GetString("accesskey")
	logger.Log(0, "joining "+node.Network+" at "+url)
	api := httpclient.JSONEndpoint[models.NodeJoinResponse, models.ErrorResponse]{
		URL:           "https://" + url,
		Route:         "/api/nodes/" + node.Network,
		Method:        http.MethodPost,
		Authorization: "Bearer " + joinData.Key,
		Headers: []httpclient.Header{
			{
				Name:  "requestfrom",
				Value: "node",
			},
		},
		Data:          joinData,
		Response:      models.NodeJoinResponse{},
		ErrorResponse: models.ErrorResponse{},
	}
	log.Println("sending join request")
	pretty.Println(joinData)
	joinResponse, errData, err := api.GetJSON(models.NodeJoinResponse{}, models.ErrorResponse{})
	if err != nil {
		if errors.Is(err, httpclient.ErrStatus) {
			logger.Log(1, "error joining network", strconv.Itoa(errData.Code), errData.Message)
		}
		return nil, nil, fmt.Errorf("error creating node %w", err)
	}
	log.Println("checking for version compatiblitity ", joinResponse.ServerConfig.Version)
	if !IsVersionComptatible(joinResponse.ServerConfig.Version) {
		return nil, nil, errors.New("incompatible server version")
	}
	logger.Log(1, "network:", node.Network, "node created on remote server...updating configs")
	pretty.Println(joinResponse)
	server := config.GetServer(joinResponse.ServerConfig.Server)
	// if new server, populate attributes
	if server == nil {
		server = &config.Server{}
		server.ServerConfig = joinResponse.ServerConfig
		server.Name = joinResponse.ServerConfig.Server
		server.MQID = config.Netclient().ID
		server.Password = config.Netclient().HostPass
		server.Nodes = make(map[string]bool)
	}
	// reset attributes that should not be changed by server

	server.Nodes[joinResponse.Node.Network] = true
	newNode := config.Node{}
	newNode.CommonNode = joinResponse.Node.CommonNode
	newNode.Connected = true
	config.UpdateHostPeers(server.Name, joinResponse.Peers)
	internetGateway, err := wireguard.UpdateWgPeers(joinResponse.Peers)
	if err != nil {
		logger.Log(0, "failed to update wg peers", err.Error())
	}
	if internetGateway != nil {
		config.Netclient().InternetGateway = *internetGateway
	}
	return &newNode, server, nil
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
