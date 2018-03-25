// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package merkletree

import (
	"bytes"
	"fmt"
	"testing"

	crypto "github.com/tendermint/go-crypto"
)

func hashBytesString(data [][]byte) string {
	var ret string
	for i := range data {
		if len(ret) == 0 {
			ret = fmt.Sprintf("%x\n", data[i])
			continue
		}
		ret = fmt.Sprintf("%v%x\n", ret, data[i])
	}
	return ret
}

func hashBytesEqual(data1, data2, hash []byte) bool {
	return bytes.Equal(hash, hashTwoBytes(data1, data2))
}

func genRandByteSlc(num, length int) [][]byte {
	slc := make([][]byte, num)
	for i := 0; i < num; i++ {
		slc[i] = crypto.CRandBytes(length)
	}
	return slc
}

func testCheckProofTree(t *testing.T, root *ProofTreeNode) bool {
	if root.IsLeaf() {
		return true
	}
	if !hashBytesEqual(root.Left.Hash, root.Right.Hash, root.Hash) {
		t.Error("node hash error", root.String())
		return false
	}
	if !testCheckProofTree(t, root.Left) {
		return false
	}
	return testCheckProofTree(t, root.Right)
}

func testCheckProofPath(t *testing.T, root *ProofTreeNode, dataSlc [][]byte) bool {
	for i := range dataSlc {
		path := root.FindProofPath(dataSlc[i])
		if !CheckMkData(root.Hash, path, dataSlc[i]) {
			t.Errorf("path err,index:%v,root:%x,path:%v\n", i, root.Hash, hashBytesString(path))
			return false
		}
	}
	return true
}

func TestGenMkRootAndProof(t *testing.T) {
	var dataLength int = 66
	var numSlc int = 20
	dataSlc := make([][][]byte, numSlc)
	for i := range dataSlc {
		dataSlc[i] = genRandByteSlc(i+1, dataLength)
	}
	for i := range dataSlc {
		root, proof := GenMkRootAndProof(dataSlc[i])
		//fmt.Println(_printProofTree(proof, ""))
		if !bytes.Equal(root, proof.Hash) {
			t.Errorf("not equal,root hash:%x,proof root:%x", root, proof.Hash)
			return
		}
		if !testCheckProofTree(t, proof) {
			t.Error("proof tree hash error")
			return
		}
	}
}

func TestCheckMkData(t *testing.T) {
	var dataLength int = 66
	var numSlc int = 20
	dataSlc := make([][][]byte, numSlc)
	for i := range dataSlc {
		dataSlc[i] = genRandByteSlc(i+1, dataLength)
	}
	for i := range dataSlc {
		root, proof := GenMkRootAndProof(dataSlc[i])
		//fmt.Println(_printProofTree(proof, ""))
		if i == 0 {
			if !bytes.Equal(root, hashBytes(dataSlc[0][0])) {
				t.Error("index 0 proof err:", _printProofTree(proof, ""))
			}
			continue
		}
		if !testCheckProofPath(t, proof, dataSlc[i]) {
			t.Error("proof path err:", i)
			return
		}
	}
}
