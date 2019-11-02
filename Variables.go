package main

import(
	"crypto/ecdsa"
	"math"
	"math/big"

	"github.com/boltdb/bolt"
)

const utxoBucket="utxoBucket"
const dbFile = "blockchain.db"
const blocksBucket = "blocks"
const genesisCoinbaseData = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
const subsidy = 10


var (
	maxNonce = math.MaxInt64
)

//挖矿难度
const targetBits = 8

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

//Block 区块结构
//时间戳
//交易 用于替换上一节的data
//前一个块的哈希
//当前块的哈希
//Nonce 工作过程参数
type Block struct {
	Timestamp     int64
	Transactions  []*Transaction
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
}

//Blockchain 是Block 指针数组
type Blockchain struct {
	tip []byte
	db  *bolt.DB
}

//BlockchainIterator 区块链迭代器用于打印区块链的信息
type BlockchainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

//TXInput 包含三个部分
//Txid: 一个交易输入引用之前的一笔交易的一个输出，ID表明是之前的那笔交易
//Vout :一笔交易可能有多个输出，Vout 为输出的索引
//ScriptSig: 提供解锁输出 Txid:Vout 的数据
type TXInput struct {
	Txid      []byte
	Vout      int
	Signature []byte
	PubKey    []byte//
}

//TXOutput 包含两个部分 Value 多少币
//ScriptPubKey:对输出进行锁定
type TXOutput struct {
	Value      int
	PubKeyHash []byte
}

//Transaction 由交易的ID,输入和输出构成
type Transaction struct {
	ID   []byte
	Vin  []TXInput
	Vout []TXOutput
}

//TXOutputs 输出集合
type TXOutputs map[int]TXOutput

// Wallets stores a collection of wallets
type Wallets struct {
	Wallets map[string]*Wallet
}



const version = byte(0x00)
const walletFile = "wallet.dat"
const addressChecksumLen = 4

// Wallet stores private and public keys
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

//MerkleTree 默克尔树数据结构
type MerkleTree struct {
    RootNode *MerkleNode
}

//MerkleNode 默克尔树节点结构
type MerkleNode struct {
    Left  *MerkleNode
    Right *MerkleNode
    Data  []byte
}
