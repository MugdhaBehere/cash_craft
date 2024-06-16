package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type CustomClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func main() {
	// Initialize Gin router
	r := gin.Default()

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Initialize database connection
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	dataSourceName := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	db, err = sql.Open("mysql", dataSourceName)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	// Create necessary tables
	if err := createTables(); err != nil {
		log.Fatalf("Error creating tables: %v", err)
	}

	// Define routes
	r.POST("/signup", signUpHandler)
	r.POST("/login", loginHandler)
	r.POST("/validateToken", validateTokenHandler)

	// Protected routes
	auth := r.Group("/")
	auth.Use(authMiddleware())
	{
		auth.POST("/transaction", transactionHandler)
		auth.POST("/viewbalance", viewBalanceHandler)
		auth.POST("/viewtransactions", viewTransactionHandler)
		auth.POST("/logout", logoutHandler)
	}

	r.Static("/", "./public")

	// Run server
	r.Run(":8080")
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token not provided"})
			c.Abort()
			return
		}

		claims, err := validateJWTToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("email", email)
		c.Next()
	}
}

// Validate the JWT token
func validateJWTToken(tokenString string) (map[string]interface{}, error) {
	// Extract the actual token string by removing the "Bearer " prefix if present
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}

	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		return nil, errors.New("SESSION_SECRET_KEY not set in environment")
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check for expected signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// Convert claims to map
		return map[string]interface{}{
			"email": claims.Email,
		}, nil
	}

	log.Printf("Invalid token claims: %v", err)
	return nil, errors.New("invalid token")
}

func createTables() error {
	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(255) NOT NULL UNIQUE,
			password VARCHAR(255) NOT NULL,
			balance DECIMAL(10, 2) DEFAULT 0.00
		)
	`)
	if err != nil {
		return fmt.Errorf("error creating users table: %w", err)
	}

	// Create transactions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS transactions (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			from_email VARCHAR(255) NOT NULL,
			to_email VARCHAR(255) NOT NULL,
			amount DECIMAL(10, 2) NOT NULL,
			type VARCHAR(50) NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("error creating transactions table: %w", err)
	}

	return nil
}

func signUpHandler(c *gin.Context) {
	var newUser User
	if err := json.NewDecoder(c.Request.Body).Decode(&newUser); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Hash the password
	hashedPassword, err := hashPassword(newUser.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	newUser.Password = hashedPassword

	// Insert user into database
	_, err = db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", newUser.Email, newUser.Password)
	if err != nil {
		log.Printf("Error inserting user into database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	log.Println("User registered successfully:", newUser.Email)
	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func loginHandler(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(c.Request.Body).Decode(&credentials); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Retrieve user from database
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE email = ?", credentials.Email).Scan(&storedPassword)
	if err != nil {
		log.Printf("Error retrieving user from database: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(credentials.Password)); err != nil {
		log.Printf("Invalid password for user %s: %v", credentials.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token, err := generateJWTToken(credentials.Email)
	if err != nil {
		log.Printf("Error generating JWT token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	log.Println("User logged in successfully:", credentials.Email)
	c.JSON(http.StatusOK, gin.H{"token": token, "message": "Login successful"})
}

func transactionHandler(c *gin.Context) {
	var transactionRequest struct {
		ToEmail   string  `json:"toEmail"`
		FromEmail string  `json:"fromEmail"`
		AmountStr string  `json:"amount"` // Use string type to handle JSON number as string
		Amount    float64 // Amount as float64 after conversion
	}

	// Decode JSON request
	if err := c.ShouldBindJSON(&transactionRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Convert AmountStr to float64
	amount, err := strconv.ParseFloat(transactionRequest.AmountStr, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid amount format"})
		return
	}
	transactionRequest.Amount = amount

	// Check if sender and recipient are the same
	if transactionRequest.FromEmail == transactionRequest.ToEmail {
		// Handle self-transaction case
		if err := updateBalance(transactionRequest.FromEmail, -transactionRequest.Amount); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Create a transaction record for the sender
		_, err = db.Exec("INSERT INTO transactions (user_id, from_email, to_email, amount, type) VALUES ((SELECT id FROM users WHERE email = ?), ?, ?, ?, 'self-transaction')",
			transactionRequest.FromEmail, transactionRequest.FromEmail, transactionRequest.ToEmail, transactionRequest.Amount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transaction record"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Transaction successful"})
		return
	}

	// Check if recipient exists
	var recipientExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", transactionRequest.ToEmail).Scan(&recipientExists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check recipient existence"})
		return
	}
	if !recipientExists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Recipient does not exist"})
		return
	}

	// Perform transaction (debit sender, credit recipient)
	if err := performTransaction(transactionRequest.FromEmail, transactionRequest.ToEmail, transactionRequest.Amount); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Create transaction record
	_, err = db.Exec("INSERT INTO transactions (user_id, from_email, to_email, amount, type) VALUES ((SELECT id FROM users WHERE email = ?), ?, ?, ?, 'transfer')",
		transactionRequest.FromEmail, transactionRequest.FromEmail, transactionRequest.ToEmail, transactionRequest.Amount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transaction record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Transaction successful"})
}

func updateBalance(email string, amount float64) error {
	_, err := db.Exec("UPDATE users SET balance = balance + ? WHERE email = ?", amount, email)
	return err
}

func performTransaction(fromEmail, toEmail string, amount float64) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Debit sender's balance
	_, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE email = ?", amount, fromEmail)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to debit sender's balance: %w", err)
	}

	// Credit recipient's balance
	_, err = tx.Exec("UPDATE users SET balance = balance + ? WHERE email = ?", amount, toEmail)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to credit recipient's balance: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func viewBalanceHandler(c *gin.Context) {
	email, exists := c.Get("email")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Email not found in context"})
		return
	}

	var balance float64
	err := db.QueryRow("SELECT balance FROM users WHERE email = ?", email).Scan(&balance)
	if err != nil {
		log.Printf("Error retrieving balance from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve balance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"balance": balance})
}

func viewTransactionHandler(c *gin.Context) {
	email, exists := c.Get("email")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Email not found in context"})
		return
	}

	var transactions []Transaction
	rows, err := db.Query("SELECT id, from_email, to_email, amount, type FROM transactions WHERE from_email = ? OR to_email = ?", email, email)
	if err != nil {
		log.Printf("Error retrieving transactions from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve transactions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var transaction Transaction
		if err := rows.Scan(&transaction.ID, &transaction.FromEmail, &transaction.ToEmail, &transaction.Amount, &transaction.Type); err != nil {
			log.Printf("Error scanning transaction row: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve transactions"})
			return
		}
		transactions = append(transactions, transaction)
	}

	c.JSON(http.StatusOK, transactions)
}

func logoutHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func generateJWTToken(email string) (string, error) {
	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		return "", errors.New("SESSION_SECRET_KEY not set in environment")
	}

	claims := CustomClaims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func validateTokenHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token not provided"})
		return
	}

	claims, err := validateJWTToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"email": claims["email"]})
}
