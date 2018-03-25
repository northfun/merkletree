// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package merkletree

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

const (
	byteslength = 32
	datanum     = 3
	indexInData = 3

	_LEFT_NODE  byte = 0x0
	_RIGHT_NODE byte = 0x1
)

// hashBytes hashes bytes data into hash code using ripemd160
func hashBytes(bys []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(bys)
	return hasher.Sum(nil)
}

// hashTwoBytes hashes two bytes datas into hash code with ripemd160
func hashTwoBytes(left, right []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(left)
	hasher.Write(right)
	return hasher.Sum(nil)
}

type ProofTreeNode struct {
	Hash  []byte
	Left  *ProofTreeNode
	Right *ProofTreeNode
}

func (ptn *ProofTreeNode) IsLeaf() bool {
	return ptn.Left == nil && ptn.Right == nil
}

func (ptn *ProofTreeNode) DataEqual(data []byte) bool {
	return bytes.Equal(ptn.Hash, data)
}

// FindProofPath find the data's proof path from the given proof tree root,
// it returns a slice filled with path data, from leaf to root, exclude root.
func (ptn *ProofTreeNode) FindProofPath(oriData []byte) [][]byte {
	var path [][]byte
	hashData := hashBytes(oriData)
	ret, find := findProofPath(ptn, path, hashData)
	if find {
		return ret
	}
	return nil
}

func findProofPath(pathNode *ProofTreeNode, path [][]byte, data []byte) ([][]byte, bool) {
	if pathNode.IsLeaf() {
		return path, pathNode.DataEqual(data)
	}
	lpath, lfind := findProofPath(pathNode.Left, path, data)
	if lfind {
		rightBytes := []byte{_RIGHT_NODE}
		return append(lpath, append(rightBytes, pathNode.Right.Hash...)), lfind
	}
	rpath, rfind := findProofPath(pathNode.Right, path, data)
	if rfind {
		leftBytes := []byte{_LEFT_NODE}
		return append(rpath, append(leftBytes, pathNode.Left.Hash...)), rfind
	}
	return path, false
}

func (prn *ProofTreeNode) String() string {
	ret := fmt.Sprintf("hash:%x\n", prn.Hash)
	if prn.Left != nil {
		ret = fmt.Sprintf("%v  left:%x\n", ret, prn.Left.Hash)
	}
	if prn.Right != nil {
		ret = fmt.Sprintf("%v  right:%x\n", ret, prn.Right.Hash)
	}
	return ret
}

func (prn *ProofTreeNode) TreeString() string {
	return _printProofTree(prn, "")
}

func _printProofTree(root *ProofTreeNode, ent string) string {
	if root.IsLeaf() {
		return ent
	}
	ret := fmt.Sprintf("%v%v", ent, root.String())
	ret = _printProofTree(root.Left, ret)
	ret = _printProofTree(root.Right, ret)
	return ret
}

// GenMkRootAndProof generates the merkle tree of parameter datas,
// it returns the root hash code and the root node of the proof tree.
func GenMkRootAndProof(datas [][]byte) ([]byte, *ProofTreeNode) {
	switch len(datas) {
	case 0:
		return nil, nil
	case 1:
		hash := hashBytes(datas[0])
		proofNode := ProofTreeNode{hash, nil, nil}
		return hash, &proofNode
	default:
		leftHash, lproof := GenMkRootAndProof(datas[:(len(datas)+1)/2])
		rightHash, rproof := GenMkRootAndProof(datas[(len(datas)+1)/2:])
		hash := hashTwoBytes(leftHash, rightHash)
		root := ProofTreeNode{hash, lproof, rproof}
		return hash, &root
	}
}

// OfflineRootCalc calculates the root hash by proof path and oriData
func OfflineRootCalc(path [][]byte, oriData []byte) []byte {
	hashData := hashBytes(oriData)
	if len(path) == 0 {
		return hashData
	}
	tmpRoot := make([]byte, len(hashData))
	copy(tmpRoot, hashData)
	for i := range path {
		switch path[i][0] {
		case _LEFT_NODE:
			tmpRoot = hashTwoBytes(path[i][1:], tmpRoot)
		case _RIGHT_NODE:
			tmpRoot = hashTwoBytes(tmpRoot, path[i][1:])
		}
	}
	return tmpRoot
}

// CheckMkData checks whether oriData hashed with merkle path equal to root hash
func CheckMkData(root []byte, path [][]byte, oriData []byte) bool {
	tmpRoot := OfflineRootCalc(path, oriData)
	return bytes.Equal(tmpRoot, root)
}
