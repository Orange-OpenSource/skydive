// +build linux

/*
 * Copyright (C) 2019 Orange.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy ofthe License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 */

package netlink

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/topology"
)

// PciFromString transforms the symbolic representation of a pci addres
// in an unsigned integer.
func PciFromString(businfo string) (uint32, error) {
	var domain, bus, device, function uint32
	_, err := fmt.Sscanf(
		businfo,
		"%04x:%02x:%02x.%01x",
		&domain, &bus, &device, &function)
	if err != nil {
		return 0, err
	}
	return ((domain << 16) | (bus << 8) | (device << 3) | function), nil
}

// PciToString transforms un unsigned integer representing a pci address in
// the symbolic representation as used by the Linux kernel.
func PciToString(address uint32) string {
	return fmt.Sprintf(
		"%04x:%02x:%02x.%01x",
		address>>16,
		(address>>8)&0xff,
		(address>>3)&0x1f,
		address&0x7)
}

/* readIntFile reads a file containing an integer. This function targets
specifically files from /sys or /proc */
func readIntFile(path string) (int, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return -1, err
	}
	result, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil {
		return -1, err
	}
	return result, nil
}

/* handleSriov adds a node for each virtual function declared. It takes
   care of finding the PCI address of each VF */
func (u *NetNsProbe) handleSriov(
	intf *graph.Node,
	metadata graph.Metadata,
	attrsVfs []netlink.VfInfo,
	name string,
) {
	var pciaddress uint32
	var err error
	var offset, stride int

	if businfoRaw, ok := metadata["BusInfo"]; !ok {
		pciaddress = 0
	} else {
		businfo := businfoRaw.(string)
		pciaddress, err = PciFromString(businfo)
		if err != nil {
			logging.GetLogger().Errorf(
				"SR-IOV: cannot parse PCI address - %s", err)
		}
		offsetFile := fmt.Sprintf(
			"/sys/bus/pci/devices/%s/sriov_offset", businfo)
		offset, err = readIntFile(offsetFile)
		if err != nil {
			logging.GetLogger().Errorf(
				"SR-IOV: cannot get offset of PCI - %s", err)
			offset = -1
		}
		strideFile := fmt.Sprintf(
			"/sys/bus/pci/devices/%s/sriov_stride", businfo)
		stride, err = readIntFile(strideFile)
		if err != nil {
			logging.GetLogger().Errorf(
				"SR-IOV: cannot get stride of PCI - %s", err)
			offset = -1
		}
	}

	for _, vf := range attrsVfs {
		mac := vf.Mac.String()
		id := vf.ID
		vfMeta := graph.Metadata{
			"Name":      fmt.Sprintf("%s.%d", name, id),
			"Type":      "sriov-device",
			"ID":        int64(id),
			"LinkState": int64(vf.LinkState),
			"MAC":       mac,
			"Qos":       int64(vf.Qos),
			"Spoofchk":  vf.Spoofchk,
			"TxRate":    int64(vf.TxRate),
			"Vlan":      int64(vf.Vlan),
		}
		if mac != "00:00:00:00:00:00" {
			vfMeta["PeerIntfMAC"] = mac
		}
		if offset >= 0 && pciaddress > 0 {
			pciVf := pciaddress + (uint32)(offset+id*stride)
			vfMeta["BusInfo"] = PciToString(pciVf)
		}
		vfNode, err := u.Graph.NewNode(graph.GenID(), vfMeta)
		if err != nil {
			logging.GetLogger().Error(err)
			continue
		}
		if _, err = topology.AddOwnershipLink(u.Graph, intf, vfNode, nil); err != nil {
			logging.GetLogger().Error(err)
		}
		if _, err = topology.AddLayer2Link(u.Graph, intf, vfNode, nil); err != nil {
			logging.GetLogger().Error(err)
		}
	}
}
