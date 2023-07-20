package functions

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
)

// RegisterSSO - payload to register via SSO
type RegisterSSO struct {
	API         string
	User        string
	Pass        string
	Network     string
	UsingSSO    bool
	AllNetworks bool
}

// RegisterWithSSO - register with user credentials with a netmaker server
func RegisterWithSSO(registerData *RegisterSSO, isGui bool) (err error) {
	if registerData == nil || len(registerData.API) == 0 { // begin validation
		return fmt.Errorf("no server data provided")
	}
	if !registerData.UsingSSO {
		if len(registerData.User) == 0 || len(registerData.Pass) == 0 {
			return fmt.Errorf("no credentials provided")
		}
	} // end validation

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
	} else {
		host.DefaultInterface = defaultInterface
	}
	shouldUpdateHost, err := doubleCheck(host, registerData.API)
	if err != nil {
		logger.FatalLog(fmt.Sprintf("error when checking host values - %v", err.Error()))
	}
	if shouldUpdateHost { // get most up to date values before submitting to server
		host = config.Netclient()
	}

	socketUrl := fmt.Sprintf("wss://%s/api/v1/auth-register/host", registerData.API)
	// Dial the netmaker server controller
	conn, _, err := websocket.DefaultDialer.Dial(socketUrl, nil)
	if err != nil {
		logger.Log(0, fmt.Sprintf("error connecting to %s : %s", registerData.API, err.Error()))
		return
	}

	request := models.RegisterMsg{
		RegisterHost: host.Host,
		User:         registerData.User,
		Password:     registerData.Pass,
		Network:      registerData.Network,
		JoinAll:      registerData.AllNetworks,
	}
	registerData.Pass = ""

	defer conn.Close()
	return handeServerSSORegisterConn(&request, registerData.API, conn, isGui)
}

func handeServerSSORegisterConn(reqMsg *models.RegisterMsg, apiURI string, conn *websocket.Conn, isGui bool) error {
	reqData, err := json.Marshal(&reqMsg)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, reqData); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				if msgType < 0 {
					logger.Log(1, "received close message from server")
					done <- struct{}{}
					return
				}
				if !strings.Contains(err.Error(), "normal") { // Error reading a message from the server
					logger.Log(0, "read:", err.Error())
				}
				return
			}

			if msgType == websocket.CloseMessage {
				logger.Log(1, "received close message from server")
				done <- struct{}{}
				return
			}
			if strings.Contains(string(msg), "oauth/register") { // TODO: maybe send to channel for GUI in future?
				fmt.Printf("Please visit:\n %s \nto authenticate\n", string(msg))
			} else {
				var response models.RegisterResponse
				if err := json.Unmarshal(msg, &response); err != nil {
					return
				}
				handleRegisterResponse(&response, isGui)
			}
		}
	}()

	for {
		select {
		case <-done:
			logger.Log(1, "finished")
			return nil
		case <-interrupt:
			logger.Log(0, "interrupt received, closing connection")
			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				logger.Log(0, "write close:", err.Error())
			}
			return err
		}
	}
}
