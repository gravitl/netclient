package functions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/posture"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
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

func prepareRegistrationHost() (schema.Host, error) {
	host := config.Netclient()
	ip, err := ncutils.GetInterfaces()
	if err != nil {
		logger.Log(0, "failed to retrieve local interfaces", err.Error())
	} else if ip != nil {
		host.Interfaces = ip
	}
	defaultInterface, err := getDefaultInterface()
	if err != nil {
		logger.Log(0, "default gateway not found", err.Error())
	} else {
		host.DefaultInterface = defaultInterface
	}
	shouldUpdateHost, err := doubleCheck(host)
	if err != nil {
		return schema.Host{}, err
	}
	if shouldUpdateHost {
		host = config.Netclient()
	}
	return host.Host, nil
}

// RegisterWithSSO - register with user credentials with a netmaker server
func RegisterWithSSO(registerData *RegisterSSO) (err error) {
	if registerData == nil || len(registerData.API) == 0 { // begin validation
		return fmt.Errorf("no server data provided")
	}
	if !registerData.UsingSSO {
		if len(registerData.User) == 0 || len(registerData.Pass) == 0 {
			return fmt.Errorf("no credentials provided")
		}
	} // end validation

	host, err := prepareRegistrationHost()
	if err != nil {
		return fmt.Errorf("error when checking host values - %w", err)
	}

	socketUrl := fmt.Sprintf("wss://%s/api/v1/auth-register/host", registerData.API)
	// Dial the netmaker server controller
	conn, _, err := websocket.DefaultDialer.Dial(socketUrl, nil)
	if err != nil {
		logger.Log(0, fmt.Sprintf("error connecting to %s : %s", registerData.API, err.Error()))
		return
	}

	posture.ApplyIdentity(&host)
	request := models.RegisterMsg{
		RegisterHost: host,
		User:         registerData.User,
		Password:     registerData.Pass,
		Network:      registerData.Network,
		JoinAll:      registerData.AllNetworks,
	}
	registerData.Pass = ""

	defer conn.Close()
	return handeServerSSORegisterConn(&request, registerData.API, conn)
}

func handeServerSSORegisterConn(reqMsg *models.RegisterMsg, apiURI string, conn *websocket.Conn) error {
	reqData, err := json.Marshal(reqMsg)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, reqData); err != nil {
		return err
	}
	done := make(chan struct{})
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)

	go func() {
		defer close(done)
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) {
					logger.Log(1, fmt.Sprintf("received close from server: %d", closeErr.Code))
					if closeErr.Text != "" {
						fmt.Printf("error registering with server %s: %s\n", apiURI, closeErr.Text)
					}
					return
				}
				logger.Log(0, "read:", err.Error())
				return
			}
			if strings.Contains(string(msg), "oauth/register") {
				fmt.Printf("Please visit:\n %s \nto authenticate\n", string(msg))
				continue
			}
			var response models.RegisterResponse
			if err := json.Unmarshal(msg, &response); err != nil {
				fmt.Printf("%s\n", string(msg))
				return
			}
			handleRegisterResponse(&response)
			return
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
