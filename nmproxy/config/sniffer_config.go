package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket/pcap"
	"github.com/gravitl/netmaker/logger"
)

// Sniffer - struct for sniffer cfg
type Sniffer struct {
	mutex           *sync.RWMutex
	stop            func()
	InboundHandler  *pcap.Handle
	OutBoundHandler *pcap.Handle
	IsRunning       bool
	InboundRouting  map[string]Routing
	OutboundRouting map[string]Routing
}

// Routing - struct for routing info
type Routing struct {
	InternalIP net.IP
	ExternalIP net.IP
}

func (c *Config) ResetSniffer() {
	c.SnifferCfg = Sniffer{
		IsRunning: false,
		mutex:     &sync.RWMutex{},
	}
}

func (c *Config) StopSniffer() {
	c.SnifferCfg.mutex.Lock()
	defer c.SnifferCfg.mutex.Unlock()
	c.SnifferCfg.stop()
}

// Config.CheckIfSnifferIsRunning - checks if sniffer is running
func (c *Config) CheckIfSnifferIsRunning() bool {
	c.SnifferCfg.mutex.RLock()
	defer c.SnifferCfg.mutex.RUnlock()
	return c.SnifferCfg.IsRunning
}

// Config.SaveRoutingInfo - saves the routing info for both inbound and outbound traffic for ext clients
func (c *Config) SaveRoutingInfo(r *Routing) {
	c.SnifferCfg.mutex.Lock()
	if c.SnifferCfg.IsRunning && r != nil {
		c.SnifferCfg.InboundRouting[r.ExternalIP.String()] = *r
		c.SnifferCfg.OutboundRouting[r.InternalIP.String()] = *r
	}
	c.SnifferCfg.mutex.Unlock()
	err := c.SetBPFFilter()
	if err != nil {
		logger.Log(0, "failed to set sniffer filters: ", err.Error())
	}
}

func (c *Config) SetSnifferHandlers(inbound, outbound *pcap.Handle, cancel context.CancelFunc) {
	c.SnifferCfg.mutex.Lock()
	defer c.SnifferCfg.mutex.Unlock()
	c.SnifferCfg.InboundHandler = inbound
	c.SnifferCfg.stop = cancel
	c.SnifferCfg.IsRunning = true
	c.SnifferCfg.OutBoundHandler = outbound
}

func (c *Config) SetBPFFilter() error {
	c.SnifferCfg.mutex.Lock()
	defer c.SnifferCfg.mutex.Unlock()

	inBoundFilter := ""
	count := 0
	for _, rInfo := range c.SnifferCfg.InboundRouting {
		if count == 0 {
			inBoundFilter = fmt.Sprintf("src %s", rInfo.ExternalIP)
		} else {
			inBoundFilter += fmt.Sprintf(" || src %s", rInfo.ExternalIP)
		}
		count++
	}

	outBoundFilter := ""
	count = 0
	for _, rInfo := range c.SnifferCfg.OutboundRouting {
		if count == 0 {
			outBoundFilter = fmt.Sprintf("dst %s", rInfo.InternalIP)
		} else {
			outBoundFilter += fmt.Sprintf(" || dst %s", rInfo.InternalIP)
		}
		count++
	}
	logger.Log(0, "Setting filters for sniffer: ", inBoundFilter, outBoundFilter)
	err := c.SnifferCfg.InboundHandler.SetBPFFilter(inBoundFilter)
	if err != nil {
		return errors.New("failed to set inbound bpf filter: " + err.Error())
	}
	err = c.SnifferCfg.OutBoundHandler.SetBPFFilter(outBoundFilter)
	if err != nil {
		return errors.New("failed to set outbound bpf filter: " + err.Error())
	}
	return nil
}

func (c *Config) GetRoutingInfo(ip string, inbound bool) (Routing, bool) {
	c.SnifferCfg.mutex.RLock()
	defer c.SnifferCfg.mutex.RUnlock()
	var rInfo Routing
	var found bool
	if inbound {
		rInfo, found = c.SnifferCfg.InboundRouting[ip]
	} else {
		rInfo, found = c.SnifferCfg.OutboundRouting[ip]
	}
	return rInfo, found
}
