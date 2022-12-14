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
	IngressRouter RouterCfg
	EgressRouter  RouterCfg
}

type RouterCfg struct {
	mutex           *sync.RWMutex
	stop            func()
	InboundHandler  *pcap.Handle
	OutBoundHandler *pcap.Handle
	IsRunning       bool
	InboundRouting  map[string]RouteInfo
	OutboundRouting map[string]RouteInfo
}

// RouteInfo - struct for routing info
type RouteInfo struct {
	InternalIP net.IP
	ExternalIP net.IP
}

// Config.ResetIngressRouter - resets the router
func (c *Config) ResetIngressRouter() {
	c.Router.IngressRouter = RouterCfg{
		mutex:           &sync.RWMutex{},
		IsRunning:       false,
		InboundRouting:  map[string]RouteInfo{},
		OutboundRouting: map[string]RouteInfo{},
	}
}

// Config.StopIngressRouter - stops the egress router
func (c *Config) StopIngressRouter() {
	c.Router.IngressRouter.mutex.Lock()
	defer c.Router.IngressRouter.mutex.Unlock()
	c.Router.IngressRouter.stop()
}

// Config.CheckIfIngressRouterIsRunning - checks if egress router is running
func (c *Config) CheckIfIngressRouterIsRunning() bool {
	c.Router.IngressRouter.mutex.RLock()
	defer c.Router.IngressRouter.mutex.RUnlock()
	return c.Router.IngressRouter.IsRunning
}

// Config.SetIngressRouterToRunning - sets the egress router status to running
func (c *Config) SetIngressRouterToRunning() {
	c.Router.IngressRouter.mutex.Lock()
	defer c.Router.IngressRouter.mutex.Unlock()
	c.Router.IngressRouter.IsRunning = true
}

// Config.SaveIngressRoutingInfo - saves the routing info for both inbound and outbound egress traffic for ext clients
func (c *Config) SaveIngressRoutingInfo(r *RouteInfo) {
	c.Router.IngressRouter.mutex.Lock()
	if c.Router.IngressRouter.IsRunning && r != nil {
		c.Router.IngressRouter.InboundRouting[r.ExternalIP.String()] = *r
		c.Router.IngressRouter.OutboundRouting[r.InternalIP.String()] = *r
	}
	c.Router.IngressRouter.mutex.Unlock()
	err := c.SetIngressBPFFilter()
	if err != nil {
		logger.Log(0, "failed to set router filters: ", err.Error())
	}
}

// Config.SetIngressRouterHandlers - sets the inbound and outbound handlers for egress router
func (c *Config) SetIngressRouterHandlers(inbound, outbound *pcap.Handle, cancel context.CancelFunc) {
	c.Router.IngressRouter.mutex.Lock()
	defer c.Router.IngressRouter.mutex.Unlock()
	c.Router.IngressRouter.InboundHandler = inbound
	c.Router.IngressRouter.stop = cancel
	c.Router.IngressRouter.IsRunning = true
	c.Router.IngressRouter.OutBoundHandler = outbound
}

// Config.SetIngressBPFFilter - sets the pcap filters for both egress inbound and outbound handlers
func (c *Config) SetIngressBPFFilter() error {
	c.Router.IngressRouter.mutex.Lock()
	defer c.Router.IngressRouter.mutex.Unlock()

	inBoundFilter := ""
	first := true
	for _, rInfo := range c.Router.IngressRouter.InboundRouting {
		if first {
			inBoundFilter = fmt.Sprintf("src %s", rInfo.ExternalIP)
			first = false
		} else {
			inBoundFilter += fmt.Sprintf(" || src %s", rInfo.ExternalIP)
		}

	}

	outBoundFilter := ""
	first = true
	for _, rInfo := range c.Router.IngressRouter.OutboundRouting {
		if first {
			outBoundFilter = fmt.Sprintf("dst %s", rInfo.InternalIP)
			first = false
		} else {
			outBoundFilter += fmt.Sprintf(" || dst %s", rInfo.InternalIP)
		}

	}

	if inBoundFilter != "" {
		logger.Log(1, "Setting filters for inbound handler: ", inBoundFilter)
		err := c.Router.IngressRouter.InboundHandler.SetBPFFilter(inBoundFilter)
		if err != nil {
			return errors.New("failed to set inbound bpf filter: " + err.Error())
		}
	}
	if outBoundFilter != "" {
		logger.Log(1, "Setting filters for outbound handler: ", outBoundFilter)
		err := c.Router.IngressRouter.OutBoundHandler.SetBPFFilter(outBoundFilter)
		if err != nil {
			return errors.New("failed to set outbound bpf filter: " + err.Error())
		}
	}

	return nil
}

// Config.GetIngressRoutingInfo - fetches the egress routing info
func (c *Config) GetIngressRoutingInfo(ip string, inbound bool) (RouteInfo, bool) {
	c.Router.IngressRouter.mutex.RLock()
	defer c.Router.IngressRouter.mutex.RUnlock()
	var rInfo RouteInfo
	var found bool
	if inbound {
		rInfo, found = c.Router.IngressRouter.InboundRouting[ip]
	} else {
		rInfo, found = c.Router.IngressRouter.OutboundRouting[ip]
	}
	return rInfo, found
}

/// EGRESSSS

// Config.ResetEgressRouter - resets the egress router
func (c *Config) ResetEgressRouter() {
	c.Router.EgressRouter = RouterCfg{
		mutex:           &sync.RWMutex{},
		IsRunning:       false,
		InboundRouting:  map[string]RouteInfo{},
		OutboundRouting: map[string]RouteInfo{},
	}
}

// Config.StopEgressRouter - stops the egress router
func (c *Config) StopEgressRouter() {
	c.Router.EgressRouter.mutex.Lock()
	defer c.Router.EgressRouter.mutex.Unlock()
	c.Router.EgressRouter.stop()
}

// Config.CheckIfEgressRouterIsRunning - checks if egress router is running
func (c *Config) CheckIfEgressRouterIsRunning() bool {
	c.Router.EgressRouter.mutex.RLock()
	defer c.Router.EgressRouter.mutex.RUnlock()
	return c.Router.EgressRouter.IsRunning
}

// Config.SetEgressRouterToRunning - sets the egress router status to running
func (c *Config) SetEgressRouterToRunning() {
	c.Router.EgressRouter.mutex.Lock()
	defer c.Router.EgressRouter.mutex.Unlock()
	c.Router.EgressRouter.IsRunning = true
}

// Config.SaveEgressRoutingInfo - saves the routing info for both inbound and outbound egress traffic for ext clients
func (c *Config) SaveEgressRoutingInfo(r *RouteInfo) {
	c.Router.EgressRouter.mutex.Lock()
	if c.Router.EgressRouter.IsRunning && r != nil {
		c.Router.EgressRouter.InboundRouting[r.ExternalIP.String()] = *r
		c.Router.EgressRouter.OutboundRouting[r.InternalIP.String()] = *r
	}
	c.Router.EgressRouter.mutex.Unlock()
	err := c.SetEgressBPFFilter()
	if err != nil {
		logger.Log(0, "failed to set router filters: ", err.Error())
	}
}

// Config.SetEgressRouterHandlers - sets the inbound and outbound handlers for egress router
func (c *Config) SetEgressRouterHandlers(inbound, outbound *pcap.Handle, cancel context.CancelFunc) {
	c.Router.EgressRouter.mutex.Lock()
	defer c.Router.EgressRouter.mutex.Unlock()
	c.Router.EgressRouter.InboundHandler = inbound
	c.Router.EgressRouter.stop = cancel
	c.Router.EgressRouter.IsRunning = true
	c.Router.EgressRouter.OutBoundHandler = outbound
}

// Config.SetEgressBPFFilter - sets the pcap filters for both egress inbound and outbound handlers
func (c *Config) SetEgressBPFFilter() error {
	c.Router.EgressRouter.mutex.Lock()
	defer c.Router.EgressRouter.mutex.Unlock()
	inBoundFilter := "dst 10.126.0.4"
	logger.Log(1, "Setting filters for egress inbound handler: ", inBoundFilter)
	err := c.Router.EgressRouter.InboundHandler.SetBPFFilter(inBoundFilter)
	if err != nil {
		return errors.New("failed to set egress inbound bpf filter: " + err.Error())
	}

	outBoundFilter := "dst 10.126.0.4"
	logger.Log(1, "Setting filters for outbound handler: ", outBoundFilter)
	err = c.Router.EgressRouter.OutBoundHandler.SetBPFFilter(outBoundFilter)
	if err != nil {
		return errors.New("failed to set egress outbound bpf filter: " + err.Error())
	}

	return nil
}

// Config.GetEgressRoutingInfo - fetches the egress routing info
func (c *Config) GetEgressRoutingInfo(ip string, inbound bool) (RouteInfo, bool) {
	c.Router.EgressRouter.mutex.RLock()
	defer c.Router.EgressRouter.mutex.RUnlock()
	var rInfo RouteInfo
	var found bool
	if inbound {
		rInfo, found = c.Router.EgressRouter.InboundRouting[ip]
	} else {
		rInfo, found = c.Router.EgressRouter.OutboundRouting[ip]
	}
	return rInfo, found
}
