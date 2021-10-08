/*
Copyright 2021 The Kubernetes Authors.

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

package graph

import (
	"fmt"
	"sync"
)

// ObjectKey is a key to identify object
type ObjectKey struct {
	ResourceType string
	Namespace    string
	Name         string
}

// NewObjectKey returns a new instance of ObjectKey
func NewObjectKey(resourceType, namespace, name string) ObjectKey {
	return ObjectKey{ResourceType: resourceType, Namespace: namespace, Name: name}
}

// Node represents a bidirectional graph node
type Node struct {
	// ToLock shouldn't be taken while FromLock is held to avoid ABBA deadlock
	ToLock  sync.RWMutex
	To      map[ObjectKey]bool
	ToCount int

	// FromLock may be taken while ToLock is held
	FromLock  sync.RWMutex
	From      map[ObjectKey]bool
	FromCount int
}

// NodeMap represents a map of graph nodes
type NodeMap struct {
	sync.RWMutex

	Nodes map[ObjectKey]*Node
}

// NewNode returns a new instance of Node
func NewNode() *Node {
	return &Node{From: map[ObjectKey]bool{}, To: map[ObjectKey]bool{}}
}

func (n *Node) addTo(key ObjectKey) {
	n.ToLock.Lock()
	defer n.ToLock.Unlock()

	if _, ok := n.To[key]; !ok {
		n.To[key] = true
		n.ToCount++
	}
}

func (n *Node) addFrom(key ObjectKey) {
	n.FromLock.Lock()
	defer n.FromLock.Unlock()

	if _, ok := n.From[key]; !ok {
		n.From[key] = true
		n.FromCount++
	}
}

func (n *Node) deleteTo(key ObjectKey) {
	n.ToLock.Lock()
	defer n.ToLock.Unlock()

	if _, ok := n.To[key]; ok {
		delete(n.To, key)
		n.ToCount--
	}
}

func (n *Node) deleteFrom(key ObjectKey) {
	n.FromLock.Lock()
	defer n.FromLock.Unlock()

	if _, ok := n.From[key]; ok {
		delete(n.From, key)
		n.FromCount--
	}
}

// NewNodeMap returns a new instance of NodeMap
func NewNodeMap() *NodeMap {
	return &NodeMap{Nodes: map[ObjectKey]*Node{}}
}

// AddEdge adds an edge from "from" node to "to" node
func (m *NodeMap) AddEdge(from, to ObjectKey) {
	m.RLock()
	defer m.RUnlock()

	fromNode := m.Nodes[from]
	fromNode.addTo(to)

	toNode := m.Nodes[to]
	toNode.addFrom(from)
}

// DeleteEdge deletes an edge from "from" node to "to" node
func (m *NodeMap) DeleteEdge(from, to ObjectKey) {
	m.RLock()
	defer m.RUnlock()

	fromNode := m.Nodes[from]
	fromNode.deleteTo(to)

	toNode := m.Nodes[to]
	toNode.deleteFrom(from)
}

// EnsureNode ensures that the node with the key exists
func (m *NodeMap) EnsureNode(key ObjectKey) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.Nodes[key]; !ok {
		m.Nodes[key] = NewNode()
	}
}

// DeleteNode deletes a node with the key
func (m *NodeMap) DeleteNode(key ObjectKey) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.Nodes[key]; ok {
		delete(m.Nodes, key)
	}
}

// DeleteNodeWithoutEdge deletes a node with the key only when it doesn't have any edges
// It returns error if it has any edges.
func (m *NodeMap) DeleteNodeWithoutEdge(key ObjectKey) error {
	m.Lock()
	defer m.Unlock()

	if n, ok := m.Nodes[key]; ok {
		n.ToLock.RLock()
		defer n.ToLock.RUnlock()

		if n.ToCount > 0 {
			return fmt.Errorf("still referenced from %d nodes", n.ToCount)
		}

		n.FromLock.RLock()
		defer n.FromLock.RUnlock()

		if n.FromCount > 0 {
			return fmt.Errorf("still referenced from %d nodes", n.FromCount)
		}

		delete(m.Nodes, key)
	}

	return nil
}

// DeleteAllToEdgesFor deletes all "To" edges for node with the key
func (m *NodeMap) DeleteAllToEdgesFor(key ObjectKey) {
	m.Lock()
	defer m.Unlock()

	n, ok := m.Nodes[key]
	if !ok {
		return
	}

	n.ToLock.Lock()
	defer n.ToLock.Unlock()

	for to := range n.To {
		if toNode, ok := m.Nodes[to]; ok {
			toNode.FromLock.Lock()
			defer toNode.FromLock.Unlock()

			// Delete the reverse reference
			delete(toNode.From, key)
			toNode.FromCount--
		}
		// Delete the reference
		delete(n.To, to)
		n.ToCount--
	}
}

// HasNode returns if node with the key exists
func (m *NodeMap) HasNode(key ObjectKey) bool {
	m.RLock()
	defer m.RUnlock()

	_, ok := m.Nodes[key]

	return ok
}

// DiffFrom returns deleted keys and added keys, by comparing the node.From for the key and new
func (m *NodeMap) DiffFrom(key ObjectKey, new map[ObjectKey]bool) (map[ObjectKey]bool, map[ObjectKey]bool) {
	m.RLock()
	defer m.RUnlock()

	deleted := map[ObjectKey]bool{}
	added := map[ObjectKey]bool{}

	n, ok := m.Nodes[key]
	if !ok {
		return deleted, new
	}

	n.FromLock.RLock()
	defer n.FromLock.RUnlock()

	for key := range n.From {
		if _, ok := new[key]; !ok {
			deleted[key] = true
		}
	}

	for key := range new {
		if _, ok := n.From[key]; !ok {
			added[key] = true
		}
	}

	return deleted, added
}

// DiffTo returns deleted keys and added keys, by comparing the node.To for the key and new
func (m *NodeMap) DiffTo(key ObjectKey, new map[ObjectKey]bool) (map[ObjectKey]bool, map[ObjectKey]bool) {
	m.RLock()
	defer m.RUnlock()

	deleted := map[ObjectKey]bool{}
	added := map[ObjectKey]bool{}

	n, ok := m.Nodes[key]
	if !ok {
		return deleted, new
	}

	n.ToLock.RLock()
	defer n.ToLock.RUnlock()

	for key := range n.To {
		if _, ok := new[key]; !ok {
			deleted[key] = true
		}
	}

	for key := range new {
		if _, ok := n.To[key]; !ok {
			added[key] = true
		}
	}

	return deleted, added
}

// GetNodeFromCount returns fromCount for the node with the key
func (m *NodeMap) GetNodeFromCount(key ObjectKey) int {
	m.RLock()
	defer m.RUnlock()

	if n, ok := m.Nodes[key]; ok {
		n.FromLock.RLock()
		defer n.FromLock.RUnlock()
		return n.FromCount
	}

	return 0
}

// GetNodeToCount returns ToCount for the node with the key
func (m *NodeMap) GetNodeToCount(key ObjectKey) int {
	m.RLock()
	defer m.RUnlock()

	if n, ok := m.Nodes[key]; ok {
		n.ToLock.RLock()
		defer n.ToLock.RUnlock()
		return n.ToCount
	}

	return 0
}
