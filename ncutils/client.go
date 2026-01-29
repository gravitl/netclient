package ncutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gravitl/netmaker/models"
	"github.com/hashicorp/go-retryablehttp"
)

type ErrStatusNotOk struct {
	Status  int
	Message string
}

func (e ErrStatusNotOk) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return fmt.Sprintf("http request failed with status %d (%s)", e.Status, http.StatusText(e.Status))
}

func SendRequest(method, endpoint string, headers http.Header, data any) (*bytes.Buffer, error) {
	var request *retryablehttp.Request
	var err error

	if data != nil {
		payload, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		request, err = retryablehttp.NewRequestWithContext(context.TODO(), method, endpoint, bytes.NewBuffer(payload))
		if err != nil {
			return nil, err
		}

		request.Header.Set("Content-Type", "application/json")
	} else {
		request, err = retryablehttp.NewRequestWithContext(context.TODO(), method, endpoint, nil)
		if err != nil {
			return nil, err
		}
	}

	for key, value := range headers {
		request.Header.Set(key, value[0])
	}

	client := retryablehttp.NewClient()
	client.RetryMax = 3
	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			// retry network errors
			return true, nil
		}

		return false, nil
	}
	client.RetryWaitMin = 5 * time.Second
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return nil, ErrStatusNotOk{
				Status: resp.StatusCode,
			}
		}

		return nil, ErrStatusNotOk{
			Status:  resp.StatusCode,
			Message: errResp.Message,
		}
	}

	var body bytes.Buffer
	_, err = io.Copy(&body, resp.Body)
	if err != nil {
		return nil, err
	}

	return &body, nil
}
