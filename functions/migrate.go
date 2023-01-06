package functions

// Migrate update data from older versions of netclient to new format
//  --- TODOD
//  --- TODOD
//  --- TODOD
// needs refactoring for updated server host/node structs
//func Migrate() {
//	if _, err := os.Stat("/etc/netclient/config"); err != nil {
//		//nothing to migrate ... exiting"
//		return
//	}
//	networks, err := config.GetSystemNetworks()
//	if err != nil {
//		logger.Log(0, "error reading network data ", err.Error())
//		return
//	}
//	host := config.Netclient()
//	for _, network := range networks {
//		logger.Log(0, "migrating", network)
//		cfg, err := config.ReadConfig(network)
//		if err != nil {
//			logger.Log(0, "could not read config for network ", network, " ", err.Error())
//		}
//		cfg.Node.HostID = host.HostID
//		cfg.Node.ListenPort = int32(host.ListenPort)
//		cfg.Node.PublicKey = host.PrivateKey.PublicKey().String()
//		cfg.Node.TrafficKeys.Mine = host.TrafficKeyPublic
//		cfg.Node.TrafficKeys.Server = []byte{}
//		cfg.Node.FirewallInUse = host.FirewallInUse
//		cfg.Node.OS = runtime.GOOS
//		//populate node and server with miminal required info to get jwt
//		serverName := strings.Replace(cfg.Server.Server, "broker.", "", 1)
//		node := config.Node{
//			ID:      cfg.Node.ID,
//			Server:  serverName,
//			Network: network,
//			Action:  cfg.Node.Password, //override
//		}
//		var tempServer config.Server
//		tempServer.API = cfg.Server.API
//		config.UpdateServer(serverName, tempServer)
//		//get jwt
//		jwt, err := config.OldAuthenticate(&node, host)
//		if err != nil {
//			logger.Log(1, "failed to authenticate for network ", network, " ", err.Error())
//			continue
//		}
//		//remove temp server
//		config.DeleteServer(cfg.Node.Server)
//		//call update node
//		api := httpclient.JSONEndpoint[models.Node, models.ErrorResponse]{
//			URL:           "https://" + cfg.Server.API,
//			Route:         "/api/nodes/" + cfg.Node.Network + "/" + cfg.Node.ID,
//			Method:        http.MethodPost,
//			Authorization: "Bearer " + jwt,
//			Headers: []httpclient.Header{
//				{
//					Name:  "requestfrom",
//					Value: "node",
//				},
//			},
//			Data:          cfg.Node,
//			Response:      models.Node{},
//			ErrorResponse: models.ErrorResponse{},
//		}
//		returnedNode, errData, err := api.GetJSON(models.Node{}, models.ErrorResponse{})
//		if err != nil {
//			if errors.Is(err, httpclient.ErrStatus) {
//				logger.Log(1, "error joining network", strconv.Itoa(errData.Code), errData.Message)
//				continue
//			}
//		}
//		//process server response
//		nodeGet := models.NodeGet{
//			Node:         returnedNode,
//			ServerConfig: cfg.Server,
//		}
//		newNode, newServer, newHost := config.ConvertOldNode(&nodeGet)
//		newNode.Connected = true
//		logger.Log(1, "network:", cfg.Node.Network, "node created on remote server...updating configs")
//		if err := config.ModPort(newHost); err != nil {
//			logger.Log(0, "error setting listen port", err.Error())
//		}
//		peers := newNode.Peers
//		for _, node := range config.GetNodes() {
//			if node.Connected {
//				peers = append(peers, node.Peers...)
//			}
//		}
//		internetGateway, _ := wireguard.UpdateWgPeers(peers)
//		if internetGateway != nil {
//			newHost.InternetGateway = *internetGateway
//		}
//		config.UpdateNodeMap(newNode.Network, *newNode)
//		newServer.Nodes[newNode.Network] = true
//		if err := config.SaveServer(newNode.Server, *newServer); err != nil {
//			logger.Log(0, "failed to save server", err.Error())
//		}
//		config.UpdateNetclient(*newHost)
//		if err := config.WriteNetclientConfig(); err != nil {
//			logger.Log(0, "error saveing netclient config", err.Error())
//		}
//		if err := config.WriteNodeConfig(); err != nil {
//			logger.Log(0, "error saveing netclient config", err.Error())
//		}
//		logger.Log(1, "joined", newNode.Network)
//	}
//	//delete old config dir
//	if err := os.RemoveAll(config.GetNetclientPath() + "config/"); err != nil {
//		logger.Log(0, "failed to delete old configuration files ", err.Error())
//	}
//}
