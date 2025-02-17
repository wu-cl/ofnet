/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofctrl

// This file implements the forwarding graph API for the flow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
)

// Small subset of openflow fields we currently support
type FlowMatch struct {
	Priority       uint16            // Priority of the flow
	InputPort      uint32            // Input port number
	MacDa          *net.HardwareAddr // Mac dest
	MacDaMask      *net.HardwareAddr // Mac dest mask
	MacSa          *net.HardwareAddr // Mac source
	MacSaMask      *net.HardwareAddr // Mac source mask
	Ethertype      uint16            // Ethertype
	VlanId         uint16            // vlan id
	VlanIdMask     *uint16           // vlan id mask
	ArpOper        uint16            // ARP Oper type
	ArpTpa         *net.IP           // Arp Tpa (target IP)
	ArpTpaMask     *net.IP           // Mask for Arp Tpa
	IpSa           *net.IP           // IPv4 source addr
	IpSaMask       *net.IP           // IPv4 source mask
	IpDa           *net.IP           // IPv4 dest addr
	IpDaMask       *net.IP           // IPv4 dest mask
	Ipv6Sa         *net.IP           // IPv6 source addr
	Ipv6SaMask     *net.IP           // IPv6 source mask
	Ipv6Da         *net.IP           // IPv6 dest addr
	Ipv6DaMask     *net.IP           // IPv6 dest mask
	IpProto        uint8             // IP protocol
	IpDscp         uint8             // DSCP/TOS field
	TcpSrcPort     uint16            // TCP source port
	TcpSrcPortMask uint16            // TCP source port mask
	TcpDstPort     uint16            // TCP dest port
	TcpDstPortMask uint16            // TCP dest port mask
	UdpSrcPort     uint16            // UDP source port
	UdpSrcPortMask uint16            // UDP source port mask
	UdpDstPort     uint16            // UDP dest port
	UdpDstPortMask uint16            // UDP dest port mask
	Metadata       *uint64           // OVS metadata
	MetadataMask   *uint64           // Metadata mask
	TunnelId       uint64            // Vxlan Tunnel id i.e. VNI
	TcpFlags       *uint16           // TCP flags
	TcpFlagsMask   *uint16           // Mask for TCP flags

	CtStates    *openflow13.CTStates
	PktMark     uint32 // NXM_NX_PKT_MARK field, in linux kernel, from skb_mark
	PktMarkMask *uint32
	Regs        []*NXRegister // NXM_NX_REGX[]
}

// NXM_NX_REGX (X in 0~15) register match field
type NXRegister struct {
	RegID int                 // register id
	Data  uint32              // register data
	Range *openflow13.NXRange // register range selection mask
}

// additional actions in flow's instruction set
type FlowAction struct {
	actionType   string           // Type of action "setVlan", "setMetadata"
	vlanId       uint16           // Vlan Id in case of "setVlan"
	macAddr      net.HardwareAddr // Mac address to set
	ipAddr       net.IP           // IP address to be set
	l4Port       uint16           // Transport port to be set
	tunnelId     uint64           // Tunnel Id (used for setting VNI)
	metadata     uint64           // Metadata in case of "setMetadata"
	metadataMask uint64           // Metadata mask
	dscp         uint8            // DSCP field

	conntrack      *ConnTrackAction
	loadAction     *NXLoadAction // Load data into NXM fields
	moveAction     *NXMoveAction // of Move action
	learnAction    *LearnAction  // flow learn action
	resubmitAction *ResubmitAction
	outputAction   *OutputAction
}

type OutputAction struct {
	actionType string
	outputPort uint32
}

type ConnTrackAction struct {
	Commit  bool
	Force   bool
	Table   *uint8
	Zone    *uint16
	Actions []openflow13.Action
}

type ResubmitAction struct {
	tableId uint8
	inPort  uint16
}

type LearnAction struct {
	idleTimeout    uint16
	hardTimeout    uint16
	priority       uint16
	cookie         uint64
	flags          uint16
	tableID        uint8
	pad            uint8
	finIdleTimeout uint16
	finHardTimeout uint16
	specs          []*openflow13.NXLearnSpec
	pad2           []byte
}

type LearnField struct {
	Name  string
	Start uint16
}

type NXLoadAction struct {
	Field *openflow13.MatchField
	Value uint64
	Range *openflow13.NXRange
}

type NXMoveAction struct {
	Length    uint16
	SrcOffset uint16
	DstOffset uint16
	SrcField  *openflow13.MatchField
	DstField  *openflow13.MatchField
}

func (f *Flow) Output(outputAction *OutputAction) error {
	action := new(FlowAction)
	action.actionType = "outputAction"
	action.outputAction = outputAction

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)

	return nil
}

func NewOutputAction(actionType string, outputPort uint32) *OutputAction {
	outputAction := new(OutputAction)
	outputAction.actionType = actionType
	outputAction.outputPort = outputPort

	return outputAction
}

func NewNXMoveAction(bitLen, srcOffset, dstOffset uint16, srcMatchFieldName, dstMatchFieldName string, hasMask bool) (*NXMoveAction, error) {
	srcMatchField, err := openflow13.FindFieldHeaderByName(srcMatchFieldName, hasMask)
	if err != nil {
		return nil, err
	}
	dstMatchField, err := openflow13.FindFieldHeaderByName(dstMatchFieldName, hasMask)
	if err != nil {
		return nil, err
	}

	return &NXMoveAction{
		Length:    bitLen,
		SrcOffset: srcOffset,
		DstOffset: dstOffset,
		SrcField:  srcMatchField,
		DstField:  dstMatchField,
	}, nil
}

func (f *Flow) MoveField(bitLen, srcOffset, dstOffset uint16, srcMatchFieldName, dstMatchFieldName string, hasMask bool) error {
	moveAct, err := NewNXMoveAction(bitLen, srcOffset, dstOffset, srcMatchFieldName, dstMatchFieldName, hasMask)
	if err != nil {
		return err
	}
	action := new(FlowAction)
	action.actionType = "moveAction"
	action.moveAction = moveAct

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func NewNXLoadAction(fieldName string, data uint64, dataRange *openflow13.NXRange) (*NXLoadAction, error) {
	field, err := openflow13.FindFieldHeaderByName(fieldName, true)
	if err != nil {
		return nil, err
	}

	return &NXLoadAction{
		Field: field,
		Range: dataRange,
		Value: data,
	}, nil
}

func (f *Flow) LoadField(fieldName string, data uint64, dataRange *openflow13.NXRange) error {
	loadAct, err := NewNXLoadAction(fieldName, data, dataRange)
	if err != nil {
		return err
	}
	action := new(FlowAction)
	action.actionType = "loadAction"
	action.loadAction = loadAct

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func NewResubmitAction(inPort *uint16, table *uint8) *ResubmitAction {
	resubmit := new(ResubmitAction)
	if inPort == nil {
		resubmit.inPort = openflow13.OFPP_IN_PORT
	} else {
		resubmit.inPort = *inPort
	}

	if table == nil {
		resubmit.tableId = openflow13.OFPTT_ALL
	} else {
		resubmit.tableId = *table
	}

	return resubmit
}

func (f *Flow) Resubmit(inPort *uint16, tableId *uint8) error {
	action := new(FlowAction)
	action.resubmitAction = NewResubmitAction(inPort, tableId)
	action.actionType = "resubmitAction"

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func NewLearnAction(tableId uint8, priority, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout uint16, cookieId uint64) *LearnAction {
	return &LearnAction{
		idleTimeout:    idleTimeout,
		hardTimeout:    hardTimeout,
		priority:       priority,
		cookie:         cookieId,
		tableID:        tableId,
		finHardTimeout: finHardTimeout,
		finIdleTimeout: finIdleTimeout,
	}
}

func (l *LearnAction) AddLearnedLoadAction(learnDstField *LearnField, learnBitLen uint16, learnSrcField *LearnField, learnSrcValue []byte) error {
	dstMatchField, err := openflow13.FindFieldHeaderByName(learnDstField.Name, true)
	if err != nil {
		return err
	}
	dstField := &openflow13.NXLearnSpecField{
		Field: dstMatchField,
		Ofs:   learnDstField.Start,
	}

	var learnSpec *openflow13.NXLearnSpec
	if learnSrcValue != nil {
		header := openflow13.NewLearnHeaderLoadFromValue(learnBitLen)
		learnSpec = getLearnSpecWithValue(header, dstField, learnSrcValue)
	} else {
		header := openflow13.NewLearnHeaderLoadFromField(learnBitLen)
		srcMatchField, err := openflow13.FindFieldHeaderByName(learnSrcField.Name, true)
		if err != nil {
			return err
		}
		srcField := &openflow13.NXLearnSpecField{
			Field: srcMatchField,
			Ofs:   learnSrcField.Start,
		}
		learnSpec = getLearnSpecWithField(header, dstField, srcField)
	}

	l.specs = append(l.specs, learnSpec)

	return nil
}

func (l *LearnAction) AddLearnedOutputAction(learnSrcField *LearnField, learnBitLen uint16) error {
	srcMatchField, err := openflow13.FindFieldHeaderByName(learnSrcField.Name, true)
	if err != nil {
		return err
	}
	srcField := &openflow13.NXLearnSpecField{
		Field: srcMatchField,
		Ofs:   learnSrcField.Start,
	}
	header := openflow13.NewLearnHeaderOutputFromField(learnBitLen)

	learnSpec := &openflow13.NXLearnSpec{
		Header:   header,
		SrcField: srcField,
	}

	l.specs = append(l.specs, learnSpec)

	return nil
}

func (l *LearnAction) AddLearnedMatch(learnDstField *LearnField, learnBitLen uint16, learnSrcField *LearnField, learnSrcValue []byte) error {
	dstMatchField, err := openflow13.FindFieldHeaderByName(learnDstField.Name, true)
	if err != nil {
		return err
	}

	dstField := &openflow13.NXLearnSpecField{
		Field: dstMatchField,
		Ofs:   learnDstField.Start,
	}

	var learnSpec *openflow13.NXLearnSpec
	if learnSrcValue != nil {
		header := openflow13.NewLearnHeaderMatchFromValue(learnBitLen)
		learnSpec = getLearnSpecWithValue(header, dstField, learnSrcValue)
	} else {
		header := openflow13.NewLearnHeaderMatchFromField(learnBitLen)
		srcMatchField, err := openflow13.FindFieldHeaderByName(learnSrcField.Name, true)
		if err != nil {
			return err
		}
		srcField := &openflow13.NXLearnSpecField{
			Field: srcMatchField,
			Ofs:   learnSrcField.Start,
		}
		learnSpec = getLearnSpecWithField(header, dstField, srcField)
	}

	l.specs = append(l.specs, learnSpec)

	return nil
}

func getLearnSpecWithValue(header *openflow13.NXLearnSpecHeader, dstField *openflow13.NXLearnSpecField, srcValue []byte) *openflow13.NXLearnSpec {
	return &openflow13.NXLearnSpec{
		Header:   header,
		DstField: dstField,
		SrcValue: srcValue,
	}
}

func getLearnSpecWithField(header *openflow13.NXLearnSpecHeader, dstField *openflow13.NXLearnSpecField, srcField *openflow13.NXLearnSpecField) *openflow13.NXLearnSpec {
	return &openflow13.NXLearnSpec{
		Header:   header,
		DstField: dstField,
		SrcField: srcField,
	}
}

func (f *Flow) Learn(learnAction *LearnAction) error {
	action := new(FlowAction)
	action.actionType = "learnAction"
	action.learnAction = learnAction

	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowActions = append(f.flowActions, action)
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func NewConntrackAction(commit bool, force bool, table *uint8, zone *uint16) *ConnTrackAction {
	return &ConnTrackAction{
		Commit: commit,
		Force:  force,
		Table:  table,
		Zone:   zone,
	}
}

func (c *ConnTrackAction) installConntrackAction() openflow13.Action {
	ctAction := openflow13.NewNXActionConnTrack()

	if c.Commit {
		ctAction.Commit()
	}
	if c.Force {
		ctAction.Force()
	}
	if c.Table != nil {
		ctAction.Table(*c.Table)
	}
	if c.Zone != nil {
		ctAction.ZoneImm(*c.Zone)
	}
	if c.Actions != nil {
		ctAction = ctAction.AddAction(c.Actions...)
	}

	return ctAction
}

// State of a flow entry
type Flow struct {
	Table       *Table        // Table where this flow resides
	Match       FlowMatch     // Fields to be matched
	NextElem    FgraphElem    // Next fw graph element
	isInstalled bool          // Is the flow installed in the switch
	FlowID      uint64        // Unique ID for the flow
	flowActions []*FlowAction // List of flow actions
	lock        sync.RWMutex  // lock for modifying flow state
}

const IP_PROTO_TCP = 6
const IP_PROTO_UDP = 17

// string key for the flow
// FIXME: simple json conversion for now. This needs to be smarter
func (self *Flow) FlowKey() string {
	jsonVal, err := json.Marshal(self.Match)
	if err != nil {
		log.Errorf("Error forming flowkey for %+v. Err: %v", self, err)
		return ""
	}

	return string(jsonVal)
}

// Fgraph element type for the flow
func (self *Flow) Type() string {
	return "flow"
}

// instruction set for flow element
func (self *Flow) GetFlowInstr() openflow13.Instruction {
	log.Fatalf("Unexpected call to get flow's instruction set")
	return nil
}

func AddPortMask(field *openflow13.MatchField, portMask uint16) {
	if portMask != 0xffff && portMask != 0x0000 {
		mask := new(openflow13.PortField)
		b := make([]byte, 16)
		binary.BigEndian.PutUint16(b, portMask)
		err := mask.UnmarshalBinary(b)
		if err != nil {
			log.Fatalf("Error addPortMask, wrong portMask:%x, err:%s.", portMask, err)
		}

		field.Mask = mask
		field.HasMask = true
		field.Length += uint8(mask.Len())
	}
}

func AddArpTpaMask(field *openflow13.MatchField, arpTpaMask *net.IP) {
	if arpTpaMask != nil {
		mask := new(openflow13.ArpXPaField)
		mask.ArpPa = *arpTpaMask

		field.Mask = mask
		field.HasMask = true
		field.Length += uint8(mask.Len())
	}
}

// Translate our match fields into openflow 1.3 match fields
func (self *Flow) xlateMatch() openflow13.Match {
	ofMatch := openflow13.NewMatch()

	// Handle input poty
	if self.Match.InputPort != 0 {
		inportField := openflow13.NewInPortField(self.Match.InputPort)
		ofMatch.AddField(*inportField)
	}

	// Handle mac DA field
	if self.Match.MacDa != nil {
		if self.Match.MacDaMask != nil {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, self.Match.MacDaMask)
			ofMatch.AddField(*macDaField)
		} else {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, nil)
			ofMatch.AddField(*macDaField)
		}
	}

	// Handle MacSa field
	if self.Match.MacSa != nil {
		if self.Match.MacSaMask != nil {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, self.Match.MacSaMask)
			ofMatch.AddField(*macSaField)
		} else {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, nil)
			ofMatch.AddField(*macSaField)
		}
	}

	// Handle ethertype
	if self.Match.Ethertype != 0 {
		etypeField := openflow13.NewEthTypeField(self.Match.Ethertype)
		ofMatch.AddField(*etypeField)
	}

	// Handle Vlan id
	if self.Match.VlanId != 0 {
		vlanIdField := openflow13.NewVlanIdField(self.Match.VlanId, self.Match.VlanIdMask)
		ofMatch.AddField(*vlanIdField)
	}

	// Handle ARP Oper type
	if self.Match.ArpOper != 0 {
		arpOperField := openflow13.NewArpOperField(self.Match.ArpOper)
		ofMatch.AddField(*arpOperField)
	}

	// Handle ARP tpa
	if self.Match.ArpTpa != nil {
		arpTpaField := openflow13.NewArpTpaField(*self.Match.ArpTpa)
		AddArpTpaMask(arpTpaField, self.Match.ArpTpaMask)
		ofMatch.AddField(*arpTpaField)
	}

	// Handle IP Dst
	if self.Match.IpDa != nil {
		if self.Match.IpDaMask != nil {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, self.Match.IpDaMask)
			ofMatch.AddField(*ipDaField)
		} else {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, nil)
			ofMatch.AddField(*ipDaField)
		}
	}

	// Handle IP Src
	if self.Match.IpSa != nil {
		if self.Match.IpSaMask != nil {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, self.Match.IpSaMask)
			ofMatch.AddField(*ipSaField)
		} else {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, nil)
			ofMatch.AddField(*ipSaField)
		}
	}

	// Handle IPv6 Dst
	if self.Match.Ipv6Da != nil {
		if self.Match.Ipv6DaMask != nil {
			ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, self.Match.Ipv6DaMask)
			ofMatch.AddField(*ipv6DaField)
		} else {
			ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, nil)
			ofMatch.AddField(*ipv6DaField)
		}
	}

	// Handle IPv6 Src
	if self.Match.Ipv6Sa != nil {
		if self.Match.Ipv6SaMask != nil {
			ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, self.Match.Ipv6SaMask)
			ofMatch.AddField(*ipv6SaField)
		} else {
			ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, nil)
			ofMatch.AddField(*ipv6SaField)
		}
	}

	// Handle IP protocol
	if self.Match.IpProto != 0 {
		protoField := openflow13.NewIpProtoField(self.Match.IpProto)
		ofMatch.AddField(*protoField)
	}

	// Handle IP dscp
	if self.Match.IpDscp != 0 {
		dscpField := openflow13.NewIpDscpField(self.Match.IpDscp)
		ofMatch.AddField(*dscpField)
	}

	// Handle port numbers
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpSrcPort != 0 {
		portField := openflow13.NewTcpSrcField(self.Match.TcpSrcPort)
		AddPortMask(portField, self.Match.TcpSrcPortMask)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpDstPort != 0 {
		portField := openflow13.NewTcpDstField(self.Match.TcpDstPort)
		AddPortMask(portField, self.Match.TcpDstPortMask)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpSrcPort != 0 {
		portField := openflow13.NewUdpSrcField(self.Match.UdpSrcPort)
		AddPortMask(portField, self.Match.UdpSrcPortMask)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpDstPort != 0 {
		portField := openflow13.NewUdpDstField(self.Match.UdpDstPort)
		AddPortMask(portField, self.Match.UdpDstPortMask)
		ofMatch.AddField(*portField)
	}

	// Handle tcp flags
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpFlags != nil {
		tcpFlagField := openflow13.NewTcpFlagsField(*self.Match.TcpFlags, self.Match.TcpFlagsMask)
		ofMatch.AddField(*tcpFlagField)
	}

	// Handle metadata
	if self.Match.Metadata != nil {
		if self.Match.MetadataMask != nil {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, self.Match.MetadataMask)
			ofMatch.AddField(*metadataField)
		} else {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, nil)
			ofMatch.AddField(*metadataField)
		}
	}

	// Handle Vxlan tunnel id
	if self.Match.TunnelId != 0 {
		tunnelIdField := openflow13.NewTunnelIdField(self.Match.TunnelId)
		ofMatch.AddField(*tunnelIdField)
	}

	if self.Match.CtStates != nil {
		ctStateField := openflow13.NewCTStateMatchField(self.Match.CtStates)
		ofMatch.AddField(*ctStateField)
	}

	// pkt_mark match
	if self.Match.PktMark != 0 {
		pktMarkField, _ := openflow13.FindFieldHeaderByName("NXM_NX_PKT_MARK", self.Match.PktMarkMask != nil)
		pktMarkField.Value = &openflow13.Uint32Message{
			Data: self.Match.PktMark,
		}
		if self.Match.PktMarkMask != nil {
			pktMarkField.Mask = &openflow13.Uint32Message{
				Data: *self.Match.PktMarkMask,
			}
		}
		ofMatch.AddField(*pktMarkField)
	}

	if self.Match.Regs != nil {
		for _, reg := range self.Match.Regs {
			registerField := openflow13.NewRegMatchField(reg.RegID, reg.Data, reg.Range)
			ofMatch.AddField(*registerField)
		}
	}

	return *ofMatch
}

// Install all flow actions
func (self *Flow) installFlowActions(flowMod *openflow13.FlowMod,
	instr openflow13.Instruction) error {
	var actInstr openflow13.Instruction
	var addActn bool = false

	// Create a apply_action instruction to be used if its not already created
	switch instr.(type) {
	case *openflow13.InstrActions:
		actInstr = instr
	default:
		actInstr = openflow13.NewInstrApplyActions()
	}

	// Loop thru all actions
	for _, flowAction := range self.flowActions {
		switch flowAction.actionType {
		case "setVlan":
			// Push Vlan Tag action
			pushVlanAction := openflow13.NewActionPushVlan(0x8100)

			// Set Outer vlan tag field
			vlanField := openflow13.NewVlanIdField(flowAction.vlanId, nil)
			setVlanAction := openflow13.NewActionSetField(*vlanField)

			// Prepend push vlan & setvlan actions to existing instruction
			actInstr.AddAction(setVlanAction, true)
			actInstr.AddAction(pushVlanAction, true)
			addActn = true

			log.Debugf("flow install. Added pushvlan action: %+v, setVlan actions: %+v",
				pushVlanAction, setVlanAction)

		case "popVlan":
			// Create pop vln action
			popVlan := openflow13.NewActionPopVlan()

			// Add it to instruction
			actInstr.AddAction(popVlan, true)
			addActn = true

			log.Debugf("flow install. Added popVlan action: %+v", popVlan)

		case "setMacDa":
			// Set Outer MacDA field
			macDaField := openflow13.NewEthDstField(flowAction.macAddr, nil)
			setMacDaAction := openflow13.NewActionSetField(*macDaField)

			// Add set macDa action to the instruction
			actInstr.AddAction(setMacDaAction, true)
			addActn = true

			log.Debugf("flow install. Added setMacDa action: %+v", setMacDaAction)

		case "setMacSa":
			// Set Outer MacSA field
			macSaField := openflow13.NewEthSrcField(flowAction.macAddr, nil)
			setMacSaAction := openflow13.NewActionSetField(*macSaField)

			// Add set macDa action to the instruction
			actInstr.AddAction(setMacSaAction, true)
			addActn = true

			log.Debugf("flow install. Added setMacSa Action: %+v", setMacSaAction)

		case "setTunnelId":
			// Set tunnelId field
			tunnelIdField := openflow13.NewTunnelIdField(flowAction.tunnelId)
			setTunnelAction := openflow13.NewActionSetField(*tunnelIdField)

			// Add set tunnel action to the instruction
			actInstr.AddAction(setTunnelAction, true)
			addActn = true

			log.Debugf("flow install. Added setTunnelId Action: %+v", setTunnelAction)

		case "setMetadata":
			// Set Metadata instruction
			metadataInstr := openflow13.NewInstrWriteMetadata(flowAction.metadata, flowAction.metadataMask)

			// Add the instruction to flowmod
			flowMod.AddInstruction(metadataInstr)

		case "setIPSa":
			// Set IP src
			ipSaField := openflow13.NewIpv4SrcField(flowAction.ipAddr, nil)
			setIPSaAction := openflow13.NewActionSetField(*ipSaField)

			// Add set action to the instruction
			actInstr.AddAction(setIPSaAction, true)
			addActn = true

			log.Debugf("flow install. Added setIPSa Action: %+v", setIPSaAction)

		case "setIPDa":
			// Set IP dst
			ipDaField := openflow13.NewIpv4DstField(flowAction.ipAddr, nil)
			setIPDaAction := openflow13.NewActionSetField(*ipDaField)

			// Add set action to the instruction
			actInstr.AddAction(setIPDaAction, true)
			addActn = true

			log.Debugf("flow install. Added setIPDa Action: %+v", setIPDaAction)

		case "setDscp":
			// Set DSCP field
			ipDscpField := openflow13.NewIpDscpField(flowAction.dscp)
			setIPDscpAction := openflow13.NewActionSetField(*ipDscpField)

			// Add set action to the instruction
			actInstr.AddAction(setIPDscpAction, true)
			addActn = true

			log.Debugf("flow install. Added setDscp Action: %+v", setIPDscpAction)

		case "setTCPSrc":
			// Set TCP src
			tcpSrcField := openflow13.NewTcpSrcField(flowAction.l4Port)
			setTCPSrcAction := openflow13.NewActionSetField(*tcpSrcField)

			// Add set action to the instruction
			actInstr.AddAction(setTCPSrcAction, true)
			addActn = true

			log.Debugf("flow install. Added setTCPSrc Action: %+v", setTCPSrcAction)

		case "setTCPDst":
			// Set TCP dst
			tcpDstField := openflow13.NewTcpDstField(flowAction.l4Port)
			setTCPDstAction := openflow13.NewActionSetField(*tcpDstField)

			// Add set action to the instruction
			actInstr.AddAction(setTCPDstAction, true)
			addActn = true

			log.Debugf("flow install. Added setTCPDst Action: %+v", setTCPDstAction)

		case "setUDPSrc":
			// Set UDP src
			udpSrcField := openflow13.NewUdpSrcField(flowAction.l4Port)
			setUDPSrcAction := openflow13.NewActionSetField(*udpSrcField)

			// Add set action to the instruction
			actInstr.AddAction(setUDPSrcAction, true)
			addActn = true

			log.Debugf("flow install. Added setUDPSrc Action: %+v", setUDPSrcAction)

		case "setUDPDst":
			// Set UDP dst
			udpDstField := openflow13.NewUdpDstField(flowAction.l4Port)
			setUDPDstAction := openflow13.NewActionSetField(*udpDstField)

			// Add set action to the instruction
			actInstr.AddAction(setUDPDstAction, true)
			addActn = true

			log.Debugf("flow install. Added setUDPDst Action: %+v", setUDPDstAction)

		case "loadAction":
			loadAct := flowAction.loadAction
			ofsBits := loadAct.Range.ToOfsBits()
			loadOfAction := openflow13.NewNXActionRegLoad(ofsBits, loadAct.Field, loadAct.Value)

			actInstr.AddAction(loadOfAction, true)
			addActn = true

			log.Debugf("Add loadAct action: %v", loadOfAction)

		case "moveAction":
			moveAct := flowAction.moveAction
			moveOfAction := openflow13.NewNXActionRegMove(moveAct.Length, moveAct.SrcOffset, moveAct.DstOffset, moveAct.SrcField, moveAct.DstField)
			actInstr.AddAction(moveOfAction, true)
			addActn = true

			log.Debugf("Add moveOfAction action: %v", moveOfAction)

		case "learnAction":
			learnAct := flowAction.learnAction
			learnAction := openflow13.NewNXActionLearn()
			learnAction.IdleTimeout = learnAct.idleTimeout
			learnAction.HardTimeout = learnAct.hardTimeout
			learnAction.Priority = learnAct.priority
			learnAction.Cookie = learnAct.cookie
			learnAction.Flags = learnAct.flags
			learnAction.TableID = learnAct.tableID
			learnAction.FinIdleTimeout = learnAct.finIdleTimeout
			learnAction.FinHardTimeout = learnAct.finHardTimeout
			learnAction.LearnSpecs = learnAct.specs

			err := actInstr.AddAction(learnAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("Add learn action: %v", learnAction)

		case "resubmitAction":
			resubmitAct := flowAction.resubmitAction
			err := actInstr.AddAction(openflow13.NewNXActionResubmitTableAction(resubmitAct.inPort, resubmitAct.tableId), false)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("Add resubmit action: %v", resubmitAct)

		case "outputAction":
			outputAct := flowAction.outputAction
			err := actInstr.AddAction(openflow13.NewActionOutput(outputAct.outputPort), false)
			if err != nil {
				return err
			}
			addActn = true
			log.Debugf("Add output Action: %v", outputAct)

		default:
			log.Fatalf("Unknown action type %s", flowAction.actionType)
		}
	}

	// Add the instruction to flow if its not already added
	if (addActn) && (actInstr != instr) {
		// Add the instrction to flowmod
		flowMod.AddInstruction(actInstr)
	}

	return nil
}

// Install a flow entry
func (self *Flow) install() error {
	// Create a flowmode entry
	flowMod := openflow13.NewFlowMod()
	flowMod.TableId = self.Table.TableId
	flowMod.Priority = self.Match.Priority
	flowMod.Cookie = self.FlowID
	flowMod.CookieMask = uint64(0xffffffffffffffff)

	// Add or modify
	if !self.isInstalled {
		flowMod.Command = openflow13.FC_ADD
	} else {
		flowMod.Command = openflow13.FC_MODIFY
	}

	// convert match fields to openflow 1.3 format
	flowMod.Match = self.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)

	// Based on the next elem, decide what to install
	switch self.NextElem.Type() {
	case "table":
		// Get the instruction set from the element
		instr := self.NextElem.GetFlowInstr()

		// Check if there are any flow actions to perform
		self.installFlowActions(flowMod, instr)

		// Add the instruction to flowmod
		flowMod.AddInstruction(instr)

		log.Debugf("flow install: added goto table instr: %+v", instr)

	case "flood":
		fallthrough
	case "output":
		// Get the instruction set from the element
		instr := self.NextElem.GetFlowInstr()

		// Add the instruction to flowmod if its not nil
		// a nil instruction means drop action
		if instr != nil {

			// Check if there are any flow actions to perform
			self.installFlowActions(flowMod, instr)

			flowMod.AddInstruction(instr)

			log.Debugf("flow install: added output port instr: %+v", instr)
		}
	case "empty":
		instr := self.NextElem.GetFlowInstr()
		if instr != nil {
			self.installFlowActions(flowMod, instr)

			if len(instr.(*openflow13.InstrActions).Actions) > 0 {
				flowMod.AddInstruction(instr)
			}
		}

		log.Debugf("flow install: added empty forwarding elem %v", instr)
	default:
		log.Fatalf("Unknown Fgraph element type %s", self.NextElem.Type())
	}

	log.Debugf("Sending flowmod: %+v", flowMod)

	// Send the message
	self.Table.Switch.Send(flowMod)

	// Mark it as installed
	self.isInstalled = true

	return nil
}

// Set Next element in the Fgraph. This determines what actions will be
// part of the flow's instruction set
func (self *Flow) Next(elem FgraphElem) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Set the next element in the graph
	self.NextElem = elem

	// Install the flow entry
	return self.install()
}

func (self *Flow) SetConntrack(connTrackAction *ConnTrackAction) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	flowMod := openflow13.NewFlowMod()
	flowMod.TableId = self.Table.TableId
	flowMod.Priority = self.Match.Priority
	flowMod.Cookie = self.FlowID
	flowMod.CookieMask = uint64(0xffffffffffffffff)

	if !self.isInstalled {
		flowMod.Command = openflow13.FC_ADD
	} else {
		flowMod.Command = openflow13.FC_MODIFY
	}

	// convert match fields to openflow 1.3 format
	flowMod.Match = self.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)

	instr := openflow13.NewInstrApplyActions()
	if instr != nil {
		ctAction := connTrackAction.installConntrackAction()
		instr.AddAction(ctAction, true)
		flowMod.AddInstruction(instr)

		log.Debugf("flow install: added output port instr: %+v", instr)
	}

	self.Table.Switch.Send(flowMod)
	self.isInstalled = true

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) SetVlan(vlanId uint16) error {
	action := new(FlowAction)
	action.actionType = "setVlan"
	action.vlanId = vlanId

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) PopVlan() error {
	action := new(FlowAction)
	action.actionType = "popVlan"

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set mac dest addr
func (self *Flow) SetMacDa(macDa net.HardwareAddr) error {
	action := new(FlowAction)
	action.actionType = "setMacDa"
	action.macAddr = macDa

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special action on the flow to set mac source addr
func (self *Flow) SetMacSa(macSa net.HardwareAddr) error {
	action := new(FlowAction)
	action.actionType = "setMacSa"
	action.macAddr = macSa

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special action on the flow to set an ip field
func (self *Flow) SetIPField(ip net.IP, field string) error {
	action := new(FlowAction)
	action.ipAddr = ip
	if field == "Src" {
		action.actionType = "setIPSa"
	} else if field == "Dst" {
		action.actionType = "setIPDa"
	} else {
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special action on the flow to set a L4 field
func (self *Flow) SetL4Field(port uint16, field string) error {
	action := new(FlowAction)
	action.l4Port = port

	switch field {
	case "TCPSrc":
		action.actionType = "setTCPSrc"
		break
	case "TCPDst":
		action.actionType = "setTCPDst"
		break
	case "UDPSrc":
		action.actionType = "setUDPSrc"
		break
	case "UDPDst":
		action.actionType = "setUDPDst"
		break
	default:
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set metadata
func (self *Flow) SetMetadata(metadata, metadataMask uint64) error {
	action := new(FlowAction)
	action.actionType = "setMetadata"
	action.metadata = metadata
	action.metadataMask = metadataMask

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) SetTunnelId(tunnelId uint64) error {
	action := new(FlowAction)
	action.actionType = "setTunnelId"
	action.tunnelId = tunnelId

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Special actions on the flow to set dscp field
func (self *Flow) SetDscp(dscp uint8) error {
	action := new(FlowAction)
	action.actionType = "setDscp"
	action.dscp = dscp

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// unset dscp field
func (self *Flow) UnsetDscp() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete to the action from db
	for idx, act := range self.flowActions {
		if act.actionType == "setDscp" {
			self.flowActions = append(self.flowActions[:idx], self.flowActions[idx+1:]...)
		}
	}

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		self.install()
	}

	return nil
}

// Delete the flow
func (self *Flow) Delete() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete from ofswitch
	if self.isInstalled {
		// Create a flowmode entry
		flowMod := openflow13.NewFlowMod()
		flowMod.Command = openflow13.FC_DELETE
		flowMod.TableId = self.Table.TableId
		flowMod.Priority = self.Match.Priority
		flowMod.Cookie = self.FlowID
		flowMod.CookieMask = uint64(0xffffffffffffffff)
		flowMod.OutPort = openflow13.P_ANY
		flowMod.OutGroup = openflow13.OFPG_ANY

		log.Debugf("Sending DELETE flowmod: %+v", flowMod)

		// Send the message
		self.Table.Switch.Send(flowMod)
	}

	// Delete it from the table
	flowKey := self.FlowKey()
	self.Table.DeleteFlow(flowKey)

	return nil
}

func InstallFlow(flow *Flow) error {
	return flow.install()
}
