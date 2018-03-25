## simple merkle tree

### generate root hash and root node of the proof tree
`func GenMkRootAndProof(datas [][]byte) ([]byte, *ProofTreeNode)`

### find proof path of oriData from proof tree
`func (ptn *ProofTreeNode) FindProofPath(oriData []byte) [][]byte`

### generate root hash by proof path and oriData
`func OfflineRootCalc(path [][]byte, oriData []byte) []byte `

### compare merkle root to make sure oriData in the tree 
`func CheckMkData(root []byte, path [][]byte, oriData []byte) bool`
