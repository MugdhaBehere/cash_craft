package main

import (
	"time"
)

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Wallet   Wallet `json:"wallet"`
}
type Wallet struct {
	Balance          float64       `json:"balance"`
	Currency         string        `json:"currency"`                   // Currency code (e.g., USD, EUR)
	LastTransaction  time.Time     `json:"last_transaction,omitempty"` // Timestamp of last transaction
	TransactionCount int           `json:"transaction_count"`
	Transactions     []Transaction `json:"transactions"`
}

type Transaction struct {
	ID        int     `json:"id"`
	FromEmail string  `json:"from_email"`
	ToEmail   string  `json:"to_email"`
	Amount    float64 `json:"amount"`
	Timestamp string  `json:"timestamp"`
	Type      string  `json:"type"`
}
