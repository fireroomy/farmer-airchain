package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type wallet struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
}

func createWalletFromPrivateKey(privateKeyHex string) (*wallet, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error converting public key to ECDSA type")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &wallet{
		privateKey: privateKey,
		address:    address,
	}, nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	readString := func(prompt string) string {
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}

	privateKeyHex := readString("Enter EVM Private Key: ")
	url := readString("Enter RPC URL: ")

	wallet, err := createWalletFromPrivateKey(privateKeyHex)
	if err != nil {
		fmt.Println("Error creating wallet:", err)
		return
	}

	expectedAddress := "0x3E6232940AE519D462b80234a3e988340E9bAB18"
	if wallet.address.Hex() != expectedAddress {
		fmt.Printf("Error: Private key does not match expected address. Got: %s, Expected: %s\n", wallet.address.Hex(), expectedAddress)
		return
	}

	fmt.Println("Address:", wallet.address.Hex())

	c, err := ethclient.Dial(url)
	if err != nil {
		panic(err)
	}

	chainId := big.NewInt(1234)

	balance, err := c.BalanceAt(context.Background(), wallet.address, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Balance:", balance)

	var mu sync.Mutex
	var nonce uint64

	// Retrieve the initial nonce
	nonce, err = c.NonceAt(context.Background(), wallet.address, nil)
	if err != nil {
		panic(err)
	}

	i := 0
	for {
		i++
		mu.Lock()
		nonce, err = sendTx(i, c, wallet.address, wallet.address, big.NewInt(int64(i%10+1)), chainId, wallet.privateKey, nonce)
		if err != nil {
			log.Printf("Failed to send transaction: %v", err)
		}
		mu.Unlock()
		time.Sleep(10 * time.Second)
	}
}

func sendTx(i int, c *ethclient.Client, from, to common.Address, amount *big.Int, chainId *big.Int, pk *ecdsa.PrivateKey, nonce uint64) (uint64, error) {
	gasPrice, err := c.SuggestGasPrice(context.Background())
	if err != nil {
		return nonce, fmt.Errorf("failed to suggest gas price: %w", err)
	}

	gasLimit := uint64(21000)

	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), pk)
	if err != nil {
		return nonce, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sender, err := types.Sender(types.NewEIP155Signer(chainId), signedTx)
	if err != nil {
		return nonce, fmt.Errorf("failed to retrieve sender from signed transaction: %w", err)
	}
	if sender != from {
		return nonce, fmt.Errorf("sender mismatch: expected %s but got %s", from.Hex(), sender.Hex())
	}

	err = c.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nonce, fmt.Errorf("failed to send transaction: %w", err)
	}

	fmt.Printf("Tx %d: %s\n", i, tx.Hash().Hex())

	return nonce + 1, nil // Increase the nonce for the next transaction
}
