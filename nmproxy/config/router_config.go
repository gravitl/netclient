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

// Router - struct for router cfg
type Router struct {
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

// Config.ResetRouter - resets the router
func (c *Config) ResetRouter() {
	c.RouterCfg = Router{
		mutex:           &sync.RWMutex{},
		IsRunning:       false,
		InboundRouting:  map[string]Routing{},
		OutboundRouting: map[string]Routing{},
	}
}

// Config.StopRouter - stops the router
func (c *Config) StopRouter() {
	c.RouterCfg.mutex.Lock()
	defer c.RouterCfg.mutex.Unlock()
	c.RouterCfg.stop()
}

// Config.CheckIfRouterIsRunning - checks if router is running
func (c *Config) CheckIfRouterIsRunning() bool {
	c.RouterCfg.mutex.RLock()
	defer c.RouterCfg.mutex.RUnlock()
	return c.RouterCfg.IsRunning
}

// Config.SetRouterToRunning - sets the router status to running
func (c *Config) SetRouterToRunning() {
	c.RouterCfg.mutex.Lock()
	defer c.RouterCfg.mutex.Unlock()
	c.RouterCfg.IsRunning = true
}

// Config.SaveRoutingInfo - saves the routing info for both inbound and outbound traffic for ext clients
func (c *Config) SaveRoutingInfo(r *Routing) {
	c.RouterCfg.mutex.Lock()
	if c.RouterCfg.IsRunning && r != nil {
		c.RouterCfg.InboundRouting[r.ExternalIP.String()] = *r
		c.RouterCfg.OutboundRouting[r.InternalIP.String()] = *r
	}
	c.RouterCfg.mutex.Unlock()
	err := c.SetBPFFilter()
	if err != nil {
		logger.Log(0, "failed to set router filters: ", err.Error())
	}
}

// Config.SetRouterHandlers - sets the inbound and outbound handlers
func (c *Config) SetRouterHandlers(inbound, outbound *pcap.Handle, cancel context.CancelFunc) {
	c.RouterCfg.mutex.Lock()
	defer c.RouterCfg.mutex.Unlock()
	c.RouterCfg.InboundHandler = inbound
	c.RouterCfg.stop = cancel
	c.RouterCfg.IsRunning = true
	c.RouterCfg.OutBoundHandler = outbound
}

// Config.SetBPFFilter - sets the pcap filters for both inbound and outbound handlers
func (c *Config) SetBPFFilter() error {
	c.RouterCfg.mutex.Lock()
	defer c.RouterCfg.mutex.Unlock()

	inBoundFilter := ""
	first := true
	for _, rInfo := range c.RouterCfg.InboundRouting {
		if first {
			inBoundFilter = fmt.Sprintf("src host %s", rInfo.ExternalIP)
			first = false
		} else {
			inBoundFilter += fmt.Sprintf(" || src host %s", rInfo.ExternalIP)
		}

	}

	outBoundFilter := ""
	first = true
	for _, rInfo := range c.RouterCfg.OutboundRouting {
		if first {
			outBoundFilter = fmt.Sprintf("dst host %s", rInfo.InternalIP)
			first = false
		} else {
			outBoundFilter += fmt.Sprintf(" || dst host %s", rInfo.InternalIP)
		}

	}

	if inBoundFilter != "" {
		logger.Log(1, "Setting filters for inbound handler: ", inBoundFilter)
		err := c.RouterCfg.InboundHandler.SetBPFFilter(inBoundFilter)
		if err != nil {
			return errors.New("failed to set inbound bpf filter: " + err.Error())
		}
	}
	if outBoundFilter != "" {
		logger.Log(1, "Setting filters for outbound handler: ", outBoundFilter)
		err := c.RouterCfg.OutBoundHandler.SetBPFFilter(outBoundFilter)
		if err != nil {
			return errors.New("failed to set outbound bpf filter: " + err.Error())
		}
	}

	return nil
}

// Config.GetRoutingInfo - fetches the routing info
func (c *Config) GetRoutingInfo(ip string, inbound bool) (Routing, bool) {
	c.RouterCfg.mutex.RLock()
	defer c.RouterCfg.mutex.RUnlock()
	var rInfo Routing
	var found bool
	if inbound {
		rInfo, found = c.RouterCfg.InboundRouting[ip]
	} else {
		rInfo, found = c.RouterCfg.OutboundRouting[ip]
	}
	return rInfo, found
}
