package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

// Load environment variables
func loadEnvVars() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

// Initialize the MySQL connection
func initDB() {
	var err error
	// Get database credentials from environment variables
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	// Format the connection string for creating the database
	connStr := fmt.Sprintf("%s:%s@tcp(%s)/", dbUser, dbPassword, dbHost)
	db, err = sql.Open("mysql", connStr)
	if err != nil {
		log.Fatal("Error connecting to the MySQL server:", err)
	}

	// Check if the database exists, if not, create it
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", dbName))
	if err != nil {
		log.Fatal("Error creating database:", err)
	}

	// Now connect to the specific database
	connStr = fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err = sql.Open("mysql", connStr)
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}

	// Check if the database connection is established
	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging the database:", err)
	}

	// Check if the tables exist, if not, create them
	createTable()
}

// Create the saree_details and users tables
func createTable() {
	// Create the saree_details table
	sareeTableCreationQuery := `
		CREATE TABLE IF NOT EXISTS saree_details (
			id VARCHAR(36) PRIMARY KEY,
			material VARCHAR(255) NOT NULL,
			price DECIMAL(10, 2) NOT NULL,
			in_date DATE NOT NULL,
			weaver VARCHAR(255),
			dyeType VARCHAR(50) NOT NULL,
			ikatType VARCHAR(50) NOT NULL
		);
	`

	// Create the users table
	usersTableCreationQuery := `
		CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(36) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			phone VARCHAR(15) NOT NULL,
			email VARCHAR(255) NOT NULL UNIQUE,
			password VARCHAR(255) NOT NULL
		);
	`

	// Execute the queries separately
	_, err := db.Exec(sareeTableCreationQuery)
	if err != nil {
		log.Fatal("Error creating saree_details table:", err)
	}

	_, err = db.Exec(usersTableCreationQuery)
	if err != nil {
		log.Fatal("Error creating users table:", err)
	}
}

// Validate email format
func isValidEmail(email string) bool {
	regex := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
	return regex.MatchString(email)
}

// Validate phone number format
func isValidPhone(phone string) bool {
	regex := regexp.MustCompile(`^[0-9]{10,15}$`)
	return regex.MatchString(phone)
}

// Register a new user
func registerUser(c *gin.Context) {
	var request struct {
		Name     string `json:"name"`
		Phone    string `json:"phone"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Bind JSON request body to struct
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	// Validate email and phone
	if !isValidEmail(request.Email) {
		c.JSON(400, gin.H{"error": "Invalid email format"})
		return
	}
	if !isValidPhone(request.Phone) {
		c.JSON(400, gin.H{"error": "Invalid phone number"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error hashing password"})
		return
	}

	// Generate unique ID for the new user
	id := uuid.New().String()

	// Insert new user into the database
	_, err = db.Exec(
		"INSERT INTO users (id, name, phone, email, password) VALUES (?, ?, ?, ?, ?)",
		id, request.Name, request.Phone, request.Email, hashedPassword,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error registering user"})
		log.Println(err)
		return
	}

	c.JSON(200, gin.H{"message": "User registered successfully"})
}

// Handle user login
func loginHandler(c *gin.Context) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Bind JSON request body to struct
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	// Query the user by email
	var user struct {
		Name     string
		Phone    string
		Password string
	}
	query := "SELECT name, phone, password FROM users WHERE email = ?"
	err := db.QueryRow(query, request.Email).Scan(&user.Name, &user.Phone, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(401, gin.H{"error": "Invalid email or password"})
		} else {
			c.JSON(500, gin.H{"error": "Database error"})
		}
		return
	}

	// Compare password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid email or password"})
		return
	}

	// Successful login
	c.JSON(200, gin.H{
		"message": "Login successful",
		"name":    user.Name,
		"phone":   user.Phone,
	})
}

func main() {
	// Load environment variables
	loadEnvVars()

	// Initialize database connection and create the database & table
	initDB()

	// Create a new Gin router
	r := gin.Default()

	// Define API endpoints
	r.POST("/api/register", registerUser) // Register user endpoint
	r.POST("/api/login", loginHandler)   // Login endpoint

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	r.Run(":" + port)
}

