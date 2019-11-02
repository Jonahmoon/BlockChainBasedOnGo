package main
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	//"encoding/hex"
	//"errors"
	"fmt"
	"io/ioutil"
	"log"
	//"math/big"
	"os"
	//"strings"
	//"time"

	//"github.com/boltdb/bolt"

	"golang.org/x/crypto/ripemd160"
)

// NewWallets creates Wallets and fills it from a file if it exists
func NewWallets() (*Wallets, error) {
	//创建钱包串
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	err := wallets.LoadFromFile()//放入文件中的钱包串

	return &wallets, err
}

//newKeyPair 新的公私钥对
func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}

// NewWallet 创建新钱包
func NewWallet() *Wallet {
	private, public := newKeyPair()//得到新的公私钥对
	wallet := Wallet{private, public}

	return &wallet
}

// CreateWallet 新创建钱包，并放入钱包串
func (ws *Wallets) CreateWallet() string {
	wallet := NewWallet()//创建新钱包
	address := fmt.Sprintf("%s", wallet.GetAddress())

	ws.Wallets[address] = wallet

	return address
}

// GetAddress 生成钱包地址
func (w Wallet) GetAddress() []byte {//自检性
	pubKeyHash := HashPubKey(w.PublicKey)//对公钥进行哈希

	versionedPayload := append([]byte{version}, pubKeyHash...)//将版本号放在公钥的哈希之后
	checksum := checksum(versionedPayload)//得到校验和

	fullPayload := append(versionedPayload, checksum...)//再把校验和放在{版本号+公钥哈希}之后
	address := Base58Encode(fullPayload)//最后再哈希一次

	return address
}


// GetAddresses 得到所有钱包的地址
func (ws *Wallets) GetAddresses() []string {
	var addresses []string

	for address := range ws.Wallets {
		addresses = append(addresses, address)
	}

	return addresses
}

// GetWallet returns a Wallet by its address
func (ws Wallets) GetWallet(address string) Wallet {
	return *ws.Wallets[address]
}

// LoadFromFile 取出钱包串
func (ws *Wallets) LoadFromFile() error {
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {//查看存放钱包文件是否存在
		return err
	}

	fileContent, err := ioutil.ReadFile(walletFile)//读取文件内容
	if err != nil {
		log.Panic(err)
	}

	var wallets Wallets//临时文件串变量
	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(fileContent))//逆序列化
	err = decoder.Decode(&wallets)
	if err != nil {
		log.Panic(err)
	}

	ws.Wallets = wallets.Wallets//放入接口钱包串
	return nil
}

// SaveToFile 将钱包串存在文件中
func (ws Wallets) SaveToFile() {
	var content bytes.Buffer

	gob.Register(elliptic.P256())//注册类型,告诉系统：可能存在Curve类型的数据要处理

	encoder := gob.NewEncoder(&content)//新的序列化器，序列化后的容放在content中
	err := encoder.Encode(ws)//将钱包序列化
	if err != nil {
		log.Panic(err)
	}

	err = ioutil.WriteFile(walletFile, content.Bytes(), 0644)//存入文件，参数依次为：文件名，文件内容，文件存储模式
	if err != nil {
		log.Panic(err)
	}
}

// HashPubKey 对公钥进行SHA256哈希
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

// ValidateAddress 检查地址有效性
func ValidateAddress(address string) bool {
	pubKeyHash := Base58Decode([]byte(address))//解压得到{XXX+checksum}
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]//得到checksum
	version := pubKeyHash[0]//得到版本号
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]//得到公钥的hash
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))//重新计算一遍checksum

	return bytes.Compare(actualChecksum, targetChecksum) == 0//看是否相等
}

// Checksum generates a checksum for a public key
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

// Lock signs the output
func (out *TXOutput) Lock(address []byte) {
	pubKeyHash := Base58Decode(address)
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
	out.PubKeyHash = pubKeyHash
}

// IsLockedWithKey checks if the output can be used by the owner of the pubkey
func (out *TXOutput) IsLockedWithKey(pubKeyHash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubKeyHash) == 0
}

// UsesKey checks whether the address initiated the transaction
func (in *TXInput) UsesKey(pubKeyHash []byte) bool {
	lockingHash := HashPubKey(in.PubKey)

	return bytes.Compare(lockingHash, pubKeyHash) == 0
}
