//go:build windows
// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Copyright (C) Netmaker contributors — Netmaker ACL manager on WFP.
 */

package wfp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	weightAllowSpecific uint8 = 15
	weightBootstrap     uint8 = 14
	weightAllowAll      uint8 = 10
	weightDefaultBlock  uint8 = 1
)

// Layer selects which WFP path a filter applies to.
type Layer int

const (
	// LayerInboundACL filters host-terminated traffic (ALE AUTH_RECV_ACCEPT).
	LayerInboundACL Layer = iota
	// LayerForwardACL filters forwarded/egress traffic (IPFORWARD).
	LayerForwardACL
)

// FilterSpec describes one allow filter.
type FilterSpec struct {
	Name       string
	Layer      Layer
	SrcNets    []net.IPNet // empty = any
	DstNets    []net.IPNet // empty = any
	Protocol   uint8       // 0 = any; 6=TCP, 17=UDP, 1=ICMP
	DstPort    uint16      // 0 = any (ignored on IPFORWARD)
	DstPortMax uint16      // if > DstPort, match inclusive range
}

type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// Engine owns a dynamic WFP session for Netmaker ACLs.
type Engine struct {
	mu        sync.Mutex
	session   uintptr
	base      *baseObjects
	ifaceLUID uint64

	inAllowAllIDs   []uint64
	fwdAllowAllIDs  []uint64
	defaultBlockIDs []uint64
	bootstrapIDs    []uint64
}

var (
	modIphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
)

// Open starts a dynamic WFP session and registers the Netmaker provider/sublayer.
func Open() (*Engine, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("Netmaker", "Netmaker ACL dynamic session")
	if err != nil {
		return nil, err
	}
	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	var handle uintptr
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return nil, wrapErr(err)
	}

	e := &Engine{session: handle}
	err = runTransaction(handle, func(s uintptr) error {
		bo, err := registerBaseObjects(s)
		if err != nil {
			return err
		}
		e.base = bo
		return nil
	})
	if err != nil {
		fwpmEngineClose0(handle)
		return nil, err
	}
	return e, nil
}

// Close destroys the dynamic session (removes all session filters).
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != 0 {
		fwpmEngineClose0(e.session)
		e.session = 0
	}
	e.inAllowAllIDs = nil
	e.fwdAllowAllIDs = nil
	e.defaultBlockIDs = nil
	e.bootstrapIDs = nil
}

// SetInterfaceAlias resolves the mesh adapter LUID and refreshes default-deny filters.
func (e *Engine) SetInterfaceAlias(alias string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == 0 {
		return errors.New("wfp engine not open")
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return nil
	}
	luid, err := interfaceLUIDByAlias(alias)
	if err != nil {
		return err
	}
	e.ifaceLUID = luid
	return e.installDefaultBlocksLocked()
}

// SetInboundDefaultAccept toggles ALE allow-all (mirrors ChangeACLInTarget).
func (e *Engine) SetInboundDefaultAccept(accept bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == 0 {
		return errors.New("wfp engine not open")
	}
	e.deleteIDsLocked(e.inAllowAllIDs)
	e.inAllowAllIDs = nil
	if !accept {
		return nil
	}
	ids, err := e.addPermitAllLocked(LayerInboundACL, weightAllowAll, "Netmaker ACL IN allow-all")
	if err != nil {
		return err
	}
	e.inAllowAllIDs = ids
	return nil
}

// SetForwardDefaultAccept toggles IPFORWARD allow-all (mirrors ChangeACLFwdTarget).
func (e *Engine) SetForwardDefaultAccept(accept bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == 0 {
		return errors.New("wfp engine not open")
	}
	e.deleteIDsLocked(e.fwdAllowAllIDs)
	e.fwdAllowAllIDs = nil
	if !accept {
		return nil
	}
	ids, err := e.addPermitAllLocked(LayerForwardACL, weightAllowAll, "Netmaker ACL FWD allow-all")
	if err != nil {
		return err
	}
	e.fwdAllowAllIDs = ids
	return nil
}

// EnsureBootstrapAllows installs DNS UDP/53 and optional metrics TCP inbound allows.
func (e *Engine) EnsureBootstrapAllows(metricsPort int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == 0 {
		return errors.New("wfp engine not open")
	}
	e.deleteIDsLocked(e.bootstrapIDs)
	e.bootstrapIDs = nil

	var ids []uint64
	dnsIDs, err := e.addFilterLocked(FilterSpec{
		Name:     "Netmaker DNS UDP 53",
		Layer:    LayerInboundACL,
		Protocol: uint8(cIPPROTO_UDP),
		DstPort:  53,
	}, weightBootstrap)
	if err != nil {
		return err
	}
	ids = append(ids, dnsIDs...)
	if metricsPort > 0 {
		mIDs, err := e.addFilterLocked(FilterSpec{
			Name:     fmt.Sprintf("Netmaker Metrics TCP %d", metricsPort),
			Layer:    LayerInboundACL,
			Protocol: uint8(cIPPROTO_TCP),
			DstPort:  uint16(metricsPort),
		}, weightBootstrap)
		if err != nil {
			return err
		}
		ids = append(ids, mIDs...)
	}
	e.bootstrapIDs = ids
	return nil
}

// AddAllow installs permit filters for the spec; returns filter IDs for later delete.
func (e *Engine) AddAllow(spec FilterSpec) ([]uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == 0 {
		return nil, errors.New("wfp engine not open")
	}
	return e.addFilterLocked(spec, weightAllowSpecific)
}

// DeleteFilters removes filters by ID.
func (e *Engine) DeleteFilters(ids []uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deleteIDsLocked(ids)
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	bo.provider, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	bo.filters, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	displayData, err := createWtFwpmDisplayData0("Netmaker", "Netmaker WFP ACL provider")
	if err != nil {
		return nil, err
	}
	provider := wtFwpmProvider0{
		providerKey: bo.provider,
		displayData: *displayData,
	}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, wrapErr(err)
	}
	subDisplay, err := createWtFwpmDisplayData0("Netmaker ACL filters", "Netmaker allow/block ACL filters")
	if err != nil {
		return nil, err
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *subDisplay,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, wrapErr(err)
	}
	return bo, nil
}

func (e *Engine) installDefaultBlocksLocked() error {
	e.deleteIDsLocked(e.defaultBlockIDs)
	e.defaultBlockIDs = nil
	if e.ifaceLUID == 0 {
		return nil
	}
	ids, err := e.addBlockAllLocked(LayerInboundACL, weightDefaultBlock, "Netmaker ACL IN default block")
	if err != nil {
		return err
	}
	fwdIDs, err := e.addBlockAllLocked(LayerForwardACL, weightDefaultBlock, "Netmaker ACL FWD default block")
	if err != nil {
		e.deleteIDsLocked(ids)
		return err
	}
	e.defaultBlockIDs = append(ids, fwdIDs...)
	return nil
}

func (e *Engine) deleteIDsLocked(ids []uint64) {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		_ = fwpmFilterDeleteById0(e.session, id)
	}
}

func (e *Engine) addPermitAllLocked(layer Layer, weight uint8, name string) ([]uint64, error) {
	return e.addFilterLocked(FilterSpec{Name: name, Layer: layer}, weight)
}

func (e *Engine) addBlockAllLocked(layer Layer, weight uint8, name string) ([]uint64, error) {
	layers := layerKeys(layer)
	var ids []uint64
	for _, lk := range layers {
		conds := make([]wtFwpmFilterCondition0, 0, 1)
		if e.ifaceLUID != 0 {
			conds = append(conds, ifaceCondition(layer, &e.ifaceLUID))
		}
		id, err := e.addRawFilter(name, lk, weight, cFWP_ACTION_BLOCK, conds, &e.ifaceLUID)
		if err != nil {
			e.deleteIDsLocked(ids)
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (e *Engine) addFilterLocked(spec FilterSpec, weight uint8) ([]uint64, error) {
	layers := layerKeys(spec.Layer)
	srcs := spec.SrcNets
	dsts := spec.DstNets
	if len(srcs) == 0 {
		srcs = []net.IPNet{{}}
	}
	if len(dsts) == 0 {
		dsts = []net.IPNet{{}}
	}

	var ids []uint64
	// Keep condition value backing memory alive for the syscall.
	var keepAlive []any

	for _, lk := range layers {
		isV6 := lk == cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 || lk == cFWPM_LAYER_IPFORWARD_V6
		for _, src := range srcs {
			for _, dst := range dsts {
				if src.IP != nil && (src.IP.To4() == nil) != isV6 {
					continue
				}
				if dst.IP != nil && (dst.IP.To4() == nil) != isV6 {
					continue
				}
				conds, alive := e.buildConditions(spec, src, dst, isV6)
				keepAlive = append(keepAlive, alive...)
				id, err := e.addRawFilter(spec.Name, lk, weight, cFWP_ACTION_PERMIT, conds, &e.ifaceLUID)
				if err != nil {
					e.deleteIDsLocked(ids)
					runtime.KeepAlive(keepAlive)
					return nil, err
				}
				ids = append(ids, id)
			}
		}
	}
	runtime.KeepAlive(keepAlive)
	return ids, nil
}

func (e *Engine) buildConditions(spec FilterSpec, src, dst net.IPNet, isV6 bool) ([]wtFwpmFilterCondition0, []any) {
	var conds []wtFwpmFilterCondition0
	var alive []any

	if e.ifaceLUID != 0 {
		conds = append(conds, ifaceCondition(spec.Layer, &e.ifaceLUID))
	}

	if src.IP != nil {
		c, a := addrCondition(spec.Layer, true, src, isV6)
		conds = append(conds, c)
		alive = append(alive, a...)
	}
	if dst.IP != nil {
		c, a := addrCondition(spec.Layer, false, dst, isV6)
		conds = append(conds, c)
		alive = append(alive, a...)
	}
	if spec.Protocol != 0 {
		conds = append(conds, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(spec.Protocol),
			},
		})
	}
	// Ports only on ALE inbound layers (not available on IPFORWARD).
	if spec.Layer == LayerInboundACL && spec.DstPort != 0 {
		if spec.DstPortMax > spec.DstPort {
			conds = append(conds,
				wtFwpmFilterCondition0{
					fieldKey:  cFWPM_CONDITION_IP_LOCAL_PORT,
					matchType: cFWP_MATCH_GREATER_OR_EQUAL,
					conditionValue: wtFwpConditionValue0{
						_type: cFWP_UINT16,
						value: uintptr(spec.DstPort),
					},
				},
				wtFwpmFilterCondition0{
					fieldKey:  cFWPM_CONDITION_IP_LOCAL_PORT,
					matchType: cFWP_MATCH_LESS_OR_EQUAL,
					conditionValue: wtFwpConditionValue0{
						_type: cFWP_UINT16,
						value: uintptr(spec.DstPortMax),
					},
				},
			)
		} else {
			conds = append(conds, wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_LOCAL_PORT,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT16,
					value: uintptr(spec.DstPort),
				},
			})
		}
	}
	return conds, alive
}

func (e *Engine) addRawFilter(name string, layer windows.GUID, weight uint8, action wtFwpActionType, conds []wtFwpmFilterCondition0, luidKeep *uint64) (uint64, error) {
	displayData, err := createWtFwpmDisplayData0(name, "")
	if err != nil {
		return 0, err
	}
	filter := wtFwpmFilter0{
		providerKey: &e.base.provider,
		subLayerKey: e.base.filters,
		weight:      filterWeight(weight),
		displayData: *displayData,
		layerKey:    layer,
		action: wtFwpmAction0{
			_type: action,
		},
	}
	if len(conds) > 0 {
		filter.numFilterConditions = uint32(len(conds))
		filter.filterCondition = &conds[0]
	}
	var id uint64
	if err := fwpmFilterAdd0(e.session, &filter, 0, &id); err != nil {
		return 0, wrapErr(err)
	}
	runtime.KeepAlive(conds)
	runtime.KeepAlive(luidKeep)
	return id, nil
}

func layerKeys(layer Layer) []windows.GUID {
	switch layer {
	case LayerForwardACL:
		return []windows.GUID{cFWPM_LAYER_IPFORWARD_V4, cFWPM_LAYER_IPFORWARD_V6}
	default:
		return []windows.GUID{cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}
	}
}

func ifaceCondition(layer Layer, luid *uint64) wtFwpmFilterCondition0 {
	field := cFWPM_CONDITION_IP_LOCAL_INTERFACE
	if layer == LayerForwardACL {
		field = cFWPM_CONDITION_IP_ARRIVAL_INTERFACE
	}
	return wtFwpmFilterCondition0{
		fieldKey:  field,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: uintptr(unsafe.Pointer(luid)),
		},
	}
}

func addrCondition(layer Layer, isSrc bool, n net.IPNet, isV6 bool) (wtFwpmFilterCondition0, []any) {
	var field windows.GUID
	switch {
	case layer == LayerForwardACL && isSrc:
		field = cFWPM_CONDITION_IP_SOURCE_ADDRESS
	case layer == LayerForwardACL && !isSrc:
		field = cFWPM_CONDITION_IP_DESTINATION_ADDRESS
	case isSrc:
		field = cFWPM_CONDITION_IP_REMOTE_ADDRESS // inbound: remote = peer/src
	default:
		field = cFWPM_CONDITION_IP_LOCAL_ADDRESS
	}

	if !isV6 {
		ip4 := n.IP.To4()
		mask4 := net.IP(n.Mask).To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		if mask4 == nil {
			mask4 = net.IP(net.CIDRMask(32, 32)).To4()
		}
		m := &wtFwpV4AddrAndMask{
			addr: binary.BigEndian.Uint32(ip4),
			mask: binary.BigEndian.Uint32(mask4),
		}
		return wtFwpmFilterCondition0{
			fieldKey:  field,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(m)),
			},
		}, []any{m}
	}

	ip6 := n.IP.To16()
	ones, _ := n.Mask.Size()
	if ip6 == nil {
		ip6 = make(net.IP, 16)
	}
	if ones == 0 && len(n.Mask) == 0 {
		ones = 128
	}
	var addr [16]uint8
	copy(addr[:], ip6)
	m := &wtFwpV6AddrAndMask{addr: addr, prefixLength: uint8(ones)}
	return wtFwpmFilterCondition0{
		fieldKey:  field,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_V6_ADDR_MASK,
			value: uintptr(unsafe.Pointer(m)),
		},
	}, []any{m}
}

func interfaceLUIDByAlias(alias string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, err
	}
	var luid uint64
	r1, _, _ := syscall.SyscallN(procConvertInterfaceAliasToLuid.Addr(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&luid)))
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return luid, nil
}

// ProtocolTCP/UDP helpers for callers.
const (
	ProtocolAny  uint8 = 0
	ProtocolICMP uint8 = 1
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
)
