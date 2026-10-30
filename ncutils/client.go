package ncutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
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

// SendRequest retries network errors. Four attempts at the 15s client timeout
// plus the 5s backoff is over a minute, which is what background sync wants
// and what an interactive logout must not wait on.
func SendRequest(method, endpoint string, headers http.Header, data any) (*bytes.Buffer, error) {
	return sendRequest(method, endpoint, headers, data, 3, 15*time.Second, 5*time.Second, 10*time.Second)
}

// SendRequestOnce performs a single attempt. Logout and disconnect use it so a
// control-plane path that is still blackholed by exit routes cannot hold the
// user for a full retry budget.
func SendRequestOnce(method, endpoint string, headers http.Header, data any, timeout time.Duration) (*bytes.Buffer, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return sendRequest(method, endpoint, headers, data, 0, timeout, 0, 0)
}

type clientConfig struct {
	retryMax                            int
	timeout, retryWaitMin, retryWaitMax time.Duration
}

// clients holds one client per config. Requests reuse its connections:
// a client per request left every connection idle until it timed out, so the
// server's proxy held thousands of them and did a TLS handshake per request.
var clients sync.Map

func getClient(cfg clientConfig) *retryablehttp.Client {
	if c, ok := clients.Load(cfg); ok {
		return c.(*retryablehttp.Client)
	}
	client := retryablehttp.NewClient()
	client.RetryMax = cfg.retryMax
	client.RetryWaitMin = cfg.retryWaitMin
	client.RetryWaitMax = cfg.retryWaitMax
	client.HTTPClient.Timeout = cfg.timeout
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
		transport.TLSHandshakeTimeout = cfg.timeout
		// A reused connection can die silently, e.g. when a NAT drops its
		// mapping. HTTP/2 keeps sending every request on it until a ping
		// goes unanswered, so ping when the connection is quiet.
		transport.HTTP2 = &http.HTTP2Config{
			SendPingTimeout: 15 * time.Second,
			PingTimeout:     5 * time.Second,
		}
		client.HTTPClient.Transport = transport
	}
	client.Logger = nil
	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			// retry network errors, on a fresh connection: the failed
			// one may be dead and would be reused otherwise
			if transport != nil {
				transport.CloseIdleConnections()
			}
			return true, nil
		}

		return false, nil
	}
	c, _ := clients.LoadOrStore(cfg, client)
	return c.(*retryablehttp.Client)
}

func sendRequest(method, endpoint string, headers http.Header, data any, retryMax int, timeout, retryWaitMin, retryWaitMax time.Duration) (*bytes.Buffer, error) {
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

	client := getClient(clientConfig{
		retryMax:     retryMax,
		timeout:      timeout,
		retryWaitMin: retryWaitMin,
		retryWaitMax: retryWaitMax,
	})
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
