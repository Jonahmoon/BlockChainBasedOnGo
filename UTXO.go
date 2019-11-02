package main

import (

	//"bytes"
	//"crypto/ecdsa"
	//"crypto/elliptic"
	//"crypto/rand"
	//"crypto/sha256"
	//"encoding/gob"
	"encoding/hex"
	//"errors"
	//"fmt"
	//"io/ioutil"
	"log"
	//"math/big"
	//"os"
	//"strings"
	//"time"

	"github.com/boltdb/bolt"

	//"golang.org/x/crypto/ripemd160"

)

//Reindex 使用 UTXO 找到未花费输出，然后在数据库中进行存储。这里就是缓存的地方。
func (bc *Blockchain) Reindex() {
	UTXO:=make(map[string]TXOutputs)
	db := bc.db
	bucketName := []byte(utxoBucket)

	err := db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(bucketName)
		_, err = tx.CreateBucket(bucketName)
		return err
	})

	//先找出所有用户，再找出所有用户的未使用交易，加入UTXO
	wallets, err := NewWallets()//创建新的钱包串，载入文件内容
	if err != nil {
		log.Panic(err)
	}
	addresses := wallets.GetAddresses()//得到地址序列

	for _,address:=range addresses{
		pubKeyHash := Base58Decode([]byte(address))//解压得到{XXX+checksum}
		pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]//得到公钥的hash
		unspentTXs:= bc.FindUnspentTransactions(pubKeyHash)
		for outid,tx:=range unspentTXs{
			ID:=hex.EncodeToString(tx.ID)
			if len(UTXO[ID])==0{
				txoutputs:=TXOutputs{}
				UTXO[ID]=txoutputs
			}
			UTXO[ID][outid]=tx.Vout[outid]//填入UTXO
		}
	}
	
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)

		for txID, outs := range UTXO {
			key, err := hex.DecodeString(txID)
			if err != nil {
				log.Panic(err)
			}
			err = b.Put(key, outs.Serialize())
		}
		return err
	})
}

// FindUnspentTransactions returns a list of transactions containing unspent outputs
func (bc *Blockchain) FindUnspentTransactions(pubKeyHash []byte) map[int]*Transaction {
	unspentTXs := make(map[int]*Transaction)//存放未使用的交易
	spentTXOs := make(map[string][]int)//已经使用过的交易
	bci := bc.Iterator()

	for {
		block := bci.Next()

		for _, tx := range block.Transactions {
			txID := hex.EncodeToString(tx.ID)

		Outputs:
			for outIdx, out := range tx.Vout {
				// Was the output spent?
				if spentTXOs[txID] != nil {
					for _, spentOutIdx := range spentTXOs[txID] {
						if spentOutIdx == outIdx {
							continue Outputs
						}
					}
				}

				if out.IsLockedWithKey(pubKeyHash) {
					unspentTXs[outIdx] = tx
				}
			}

			if tx.IsCoinbase() == false {
				for _, in := range tx.Vin {
					if in.UsesKey(pubKeyHash) {
						inTxID := hex.EncodeToString(in.Txid)
						spentTXOs[inTxID] = append(spentTXOs[inTxID], in.Vout)
					}
				}
			}
		}

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return unspentTXs
}


//Update 更新UTXOSet
func (bc *Blockchain) Update(block *Block) {
	db := bc.db

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))

		for _, tx := range block.Transactions {
			if tx.IsCoinbase() == false {
				for _, vin := range tx.Vin {
					updatedOuts :=TXOutputs{}
					outsBytes := b.Get(vin.Txid)//根据交易号拿到对应的未使用输出
					outs := DeserializeOutputs(outsBytes)

					for outIdx, out := range outs {
						if outIdx != vin.Vout {
							updatedOuts[vin.Vout] = out
						}
					}

					if len(updatedOuts) == 0 {
						err := b.Delete(vin.Txid)
						if err != nil {
							log.Panic(err)
						}
					} else {
						err := b.Put(vin.Txid, updatedOuts.Serialize())
						if err != nil {
							log.Panic(err)
						}
					}

				}
			}

			newOutputs := TXOutputs{}
			for i, out := range tx.Vout {
				newOutputs[i] =out
			}

			err := b.Put(tx.ID, newOutputs.Serialize())
			if err != nil {
				log.Panic(err)
			}
			
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

//FindUTXO 在UTXO中查询pubKeyHash所有者的余额
func (bc *Blockchain) FindUTXO(pubKeyHash []byte) []TXOutput {
	var UTXOs []TXOutput
	db := bc.db

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			outs := DeserializeOutputs(v)

			for _, out := range outs {
				if out.IsLockedWithKey(pubKeyHash) {
					UTXOs = append(UTXOs, out)
				}
			}
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return UTXOs
}

//FindSpendableOutputs 找到可花费的输出，返回交易ID和输出ID的map
func (bc *Blockchain) FindSpendableOutputs(pubkeyHash []byte, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0
	db := bc.db

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			txID := hex.EncodeToString(k)
			outs := DeserializeOutputs(v)

			for outIdx, out := range outs {
				if out.IsLockedWithKey(pubkeyHash) && accumulated < amount {
					accumulated += out.Value
					unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return accumulated, unspentOutputs
}

// NewUTXOTransaction creates a new transaction
func NewUTXOTransaction(from, to string, amount int, bc *Blockchain) *Transaction {
	var inputs []TXInput
	var outputs []TXOutput

	wallets, err := NewWallets()
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet(from)//拿出钱包
	pubKeyHash := HashPubKey(wallet.PublicKey)
	acc, validOutputs := bc.FindSpendableOutputs(pubKeyHash, amount)

	if acc < amount {
		log.Panic("ERROR: Not enough funds")
	}

	// Build a list of inputs
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			log.Panic(err)
		}

		for _, out := range outs {
			input := TXInput{txID, out, nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Build a list of outputs
	if to==from{
		outputs = append(outputs, *NewTXOutput(acc, to))//如果是自己给自己，只有一个输出，相当于零钱找整钱
	}else{
		outputs = append(outputs, *NewTXOutput(amount, to))//给to的钱
		if acc > amount {
			outputs = append(outputs, *NewTXOutput(acc-amount, from)) // 找零
		}
	}

	tx := Transaction{nil, inputs, outputs}
	tx.ID = tx.Hash()
	bc.SignTransaction(&tx, wallet.PrivateKey)

	return &tx
}


