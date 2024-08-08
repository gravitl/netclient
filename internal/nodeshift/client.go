package nodeshift

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/devilcove/httpclient"
	"github.com/gravitl/netmaker/models"
)

type request struct {
	ID      int    `json:"id"`
	Uuid    string `json:"uuid"`
	Network string `json:"network"`
}

type response struct {
	Message string `json:"message"`
}

const (
	backendHostProduction  = "app.nodeshift.com"
	backendHostStaging     = "app.nodeshift.co"
	backendHostDevelopment = "app.nodeshift.local"
)

var errUnknownServerType = errors.New("unknown server type")

func Notify(event models.HostUpdate) error {
	if event.Action != models.JoinHostToNetwork {
		return nil
	}

	backendHost, vpcID, err := getIDHost(event.Node.Server)
	if err != nil {
		return fmt.Errorf("failed to get sever and backendHost: %s", err)
	}

	api := httpclient.JSONEndpoint[response, response]{
		URL:    "https://" + backendHost,
		Route:  "/api/vpc/register",
		Method: http.MethodPost,
		Data: request{
			ID:      vpcID,
			Uuid:    event.Node.ID.String(),
			Network: event.Node.Network,
		},
		Response:      response{},
		ErrorResponse: response{},
	}

	_, errData, err := api.GetJSON(response{}, response{})
	if err != nil {
		if strings.Contains(errData.Message, "success") {
			return nil
		}

		return err
	}

	return nil
}

func getIDHost(server string) (string, int, error) {
	r, err := regexp.Compile(`.*-([0-9]+)\..*`)
	if err != nil {
		return "", 0, fmt.Errorf("failed to compile regex: %s", err)
	}

	matches := r.FindStringSubmatch(server)
	if len(matches) != 2 {
		return "", 0, fmt.Errorf("failed to find vpc id: %v", matches)
	}

	id, err := strconv.Atoi(matches[1])
	if err != nil {
		return "", 0, fmt.Errorf("failed to convert id to int: %s", err)
	}

	if strings.HasSuffix(server, "nodeshift.network") {
		return backendHostProduction, id, nil
	} else if strings.HasSuffix(server, "nodeshift.co") {
		return backendHostStaging, id, nil
	} else if strings.HasSuffix(server, "nodeshift.cloud") {
		return backendHostDevelopment, id, nil
	}

	return "", 0, errUnknownServerType
}
