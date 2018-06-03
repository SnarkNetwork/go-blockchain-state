package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"

	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
)

const subsidy = 10

// Transaction represents an Ethereum transaction
type Transaction struct {
	ID         []byte
	From       []byte
	To         []byte
	Val  			 uint64
	Balance    uint64
	Sig 			 []byte
	Hash			 []byte
	PrevHash	 []byte
}

// IsCoinbase checks whether the transaction is coinbase
func (tx Transaction) IsCoinbase() bool {
	return len(tx.From) == 0
}

// Serialize returns a serialized Transaction
func (tx Transaction) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

// Hash returns the hash of the Transaction
func (tx *Transaction) Hash() []byte {
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = []byte{}

	hash = sha256.Sum256(txCopy.Serialize())

	return hash[:]
}

// Sign signs each input of a Transaction
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs Transaction) {
	if tx.IsCoinbase() {
		return
	}

	txCopy := tx.TrimmedCopy()

	dataToSign := fmt.Sprintf("%x\n", txCopy)

	r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(dataToSign))
	if err != nil {
		log.Panic(err)
	}
	signature := append(r.Bytes(), s.Bytes()...)

	tx.Signature = signature
}

// String returns a human-readable representation of a transaction
func (tx Transaction) String() string {
	var lines []string

	lines = append(lines, fmt.Sprintf("--- Transaction %x:", tx.ID))
	lines = append(lines, fmt.Sprintf("     From %x:", tx))
	lines = append(lines, fmt.Sprintf("     To %x:", tx))
	lines = append(lines, fmt.Sprintf("     Val %d:", tx))
	lines = append(lines, fmt.Sprintf("     Sig %x:", tx))
	lines = append(lines, fmt.Sprintf("     PubKey %x:", tx))
	lines = append(lines, fmt.Sprintf("     PubKeyHash %x:", tx))
	lines = append(lines, fmt.Sprintf("     Hash %x:", tx))
	lines = append(lines, fmt.Sprintf("     PrevHash %x:", tx))
	lines = append(lines, fmt.Sprintf("     Balance %d:", tx))

	return strings.Join(lines, "\n")
}

// TrimmedCopy creates a trimmed copy of Transaction to be used in signing
func (tx *Transaction) TrimmedCopy() Transaction {
	return Transaction{tx.ID, tx.From, tx.To, tx.Val, tx.Balance, nil, nil, tx.PrevHash}
}

// Verify verifies signatures of Transaction inputs
func (tx *Transaction) Verify(prevTXs Transaction) bool {
	if tx.IsCoinbase() {
		return true
	}

	if prevTXs.ID == nil {
		log.Panic("ERROR: Previous transaction is not correct")
	}

	txCopy := tx.TrimmedCopy()
	curve := elliptic.P256()

	r := big.Int{}
	s := big.Int{}
	sigLen := len(txCopy.Signature)
	r.SetBytes(txCopy.Signature[:(sigLen / 2)])
	s.SetBytes(txCopy.Signature[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(txCopy.From)
	x.SetBytes(txCopy.From[:(keyLen / 2)])
	y.SetBytes(txCopy.From[(keyLen / 2):])

	dataToVerify := fmt.Sprintf("%x\n", txCopy)

	rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&rawPubKey, []byte(dataToVerify), &r, &s) == false {
		return false
	}

	return true
}

// NewCoinbaseTX creates a new coinbase transaction
func NewCoinbaseTX(to, data string) *Transaction {
	if data == "" {
		randData := make([]byte, 20)
		_, err := rand.Read(randData)
		if err != nil {
			log.Panic(err)
		}

		data = fmt.Sprintf("%x", randData)
	}
	tx := Transaction{nil, nil, to, 10, 10, nil, nil, nil}
	tx.ID = tx.Hash()

	return &tx
}

// NewTransaction creates a new transaction
func NewTransaction(wallet *Wallet, to string, amount int) *Transaction {
	from := HashPubKey(wallet.PublicKey)
	//state.getBalance
	prevTx, bal := State.GetBalance(pubKeyHash)

	if bal < amount {
		log.Panic("ERROR: Not enough funds")
	}

	tx := Transaction{nil, from, to, amount, bal-amount, nil, nil, prevTx.PrevHash}
	tx.ID = tx.Hash()
	State.Blockchain.SignTransaction(&tx, wallet.PrivateKey)
	tx.Sign(privKey, prevTx)
	return &tx
}

// DeserializeTransaction deserializes a transaction
func DeserializeTransaction(data []byte) Transaction {
	var transaction Transaction

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&transaction)
	if err != nil {
		log.Panic(err)
	}

	return transaction
}
