// +build !linux

/*
 * Copyright (C) 2015 Red Hat, Inc.
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
	"github.com/skydive-project/skydive/common"
	"github.com/skydive-project/skydive/graffiti/graph"
)

// Probe describes a list NetLink NameSpace probe to enhance the graph
type Probe struct {
}

// Start the probe
func (u *Probe) Start() {
}

// Stop the probe
func (u *Probe) Stop() {
}

// NewProbe creates a new netlink probe
func NewProbe(g *graph.Graph, n *graph.Node) (*Probe, error) {
	return nil, common.ErrNotImplemented
}
