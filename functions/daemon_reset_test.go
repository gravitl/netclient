//go:build linux

package functions

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse/paho.mqtt.golang"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type resetMessage struct {
	mqtt.Message
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	topic   string
	payload []byte
}

func (m *resetMessage) Topic() string {
	if m.entered != nil {
		m.once.Do(func() { close(m.entered); <-m.release })
	}
	if m.topic != "" {
		return m.topic
	}
	return "peers/host/test-host/example.com"
}
func (m *resetMessage) Payload() []byte { return m.payload }
func TestResetKeepsOldHandlersOffTheFirewall(t *testing.T) {
	oldFwClose := config.FwClose
	var fwClosed atomic.Bool
	config.FwClose = func() { fwClosed.Store(true); runtime.Goexit() }
	t.Cleanup(func() { config.FwClose = oldFwClose })
	msg := &resetMessage{entered: make(chan struct{}), release: make(chan struct{})}
	go HostPeerUpdate(nil, msg)
	<-msg.entered
	resetDone := make(chan struct{})
	go func() { defer close(resetDone); resetDaemonInProcess(func() {}, &sync.WaitGroup{}) }()
	var release sync.Once
	defer func() { release.Do(func() { close(msg.release) }); <-resetDone }()
	time.Sleep(200 * time.Millisecond)
	if fwClosed.Load() {
		t.Fatal("reset closed the firewall while a handler was still applying an update")
	}
	release.Do(func() { close(msg.release) })
	<-resetDone
	if !fwClosed.Load() {
		t.Fatal("reset finished without closing the firewall")
	}
}
func encryptedMessage(t *testing.T, topic string, body any) *resetMessage {
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	zw.Write(raw)
	require.NoError(t, zw.Close())
	block, err := aes.NewCipher(config.Netclient().TrafficKeyPublic)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return &resetMessage{topic: topic, payload: gcm.Seal(nonce, nonce, zipped.Bytes(), nil)}
}
func TestHandlersReleaseResetMuBeforeHardRestart(t *testing.T) {
	const serverName = "nm.example.com"
	host := config.Netclient()
	prevVersion, prevServers, prevNodes, prevCurr := config.Version, config.Servers, config.Nodes, config.CurrServer
	prevPub, prevPriv, prevUseVersion, prevHardRestart := host.TrafficKeyPublic, host.TrafficKeyPrivate, useVersion, hardRestart
	t.Cleanup(func() {
		config.Version, config.Servers, config.Nodes, config.CurrServer = prevVersion, prevServers, prevNodes, prevCurr
		host.TrafficKeyPublic, host.TrafficKeyPrivate, useVersion, hardRestart = prevPub, prevPriv, prevUseVersion, prevHardRestart
	})
	config.Version, config.CurrServer = "v1.0.0", serverName
	host.TrafficKeyPublic, host.TrafficKeyPrivate = bytes.Repeat([]byte{7}, 32), nil
	config.Servers = map[string]config.Server{serverName: {Name: serverName, ServerConfig: models.ServerConfig{Version: "v1.0.1"}}}
	config.Nodes = config.NodeMap{"net": {}}
	useVersion = func(string, bool) (skip bool, err error) { return false, nil }
	for _, tc := range []struct {
		handler func(mqtt.Client, mqtt.Message)
		topic   string
		body    any
		openrc  bool
	}{
		{HostUpdate, "host/update/test-host/" + serverName, models.HostUpdate{Action: models.Upgrade}, false},
		{HostPeerUpdate, "peers/host/test-host/" + serverName, models.HostPeerUpdate{ServerVersion: "v1.0.1", Host: schema.Host{AutoUpdate: true}}, false},
		{HostPeerUpdate, "peers/host/test-host/" + serverName, models.HostPeerUpdate{ServerVersion: "v1.0.1", Host: schema.Host{AutoUpdate: true}, Peers: []wgtypes.PeerConfig{{}}}, true},
	} {
		t.Run(tc.topic, func(t *testing.T) {
			if tc.openrc {
				hardRestart = func() error { return nil }
				prevPeers := host.HostPeers
				t.Cleanup(func() { config.UpdateHostPeers(prevPeers) })
				config.UpdateHostPeers(nil)
				tc.handler(mqtt.NewClient(mqtt.NewClientOptions()), encryptedMessage(t, tc.topic, tc.body))
				if len(config.Netclient().HostPeers) != 0 || !resetMu.TryLock() {
					t.Fatal("handler went on with the old update after the restart")
				}
				resetMu.Unlock()
				return
			}
			restarting, unblock, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			// The real restart stops this process: unwind the upgrade mutex it would unlock.
			hardRestart = func() error { close(restarting); <-unblock; upgMutex.Unlock(); runtime.Goexit(); return nil }
			msg := encryptedMessage(t, tc.topic, tc.body)
			go func() { defer close(done); tc.handler(mqtt.NewClient(mqtt.NewClientOptions()), msg) }()
			select {
			case <-restarting:
			case <-time.After(30 * time.Second):
				t.Fatal("handler never reached the hard restart")
			}
			if !resetMu.TryLock() {
				t.Fatal("reset cannot take resetMu while the handler runs a hard restart")
			}
			close(unblock)
			<-done
			resetMu.Unlock()
		})
	}
}
