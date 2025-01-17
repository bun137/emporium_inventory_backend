package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
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

	// Check if the table exists, if not, create it
	createTable()
}

// Create the saree_details table with weaver allowed to be NULL
func createTable() {
	// Create the saree_details table
	tableCreationQuery := `
		CREATE TABLE IF NOT EXISTS saree_details (
			id VARCHAR(36) PRIMARY KEY,
			material VARCHAR(255) NOT NULL,
			price DECIMAL(10, 2) NOT NULL,
			in_date DATE NOT NULL,
			weaver VARCHAR(255),      -- We remove NOT NULL, allowing NULL
			dyeType VARCHAR(50) NOT NULL,
			ikatType VARCHAR(50) NOT NULL
		);
	`
	_, err := db.Exec(tableCreationQuery)
	if err != nil {
		log.Fatal("Error creating table:", err)
	}
}

// Save saree details into the database
func saveSareeDetails(c *gin.Context) {
	var request struct {
		Material string  `json:"material"`
		Price    float64 `json:"price"`
		InDate   string  `json:"inDate"`
		Weaver   *string `json:"weaver"`    // Weaver can now be NULL, so we use a pointer to string
		DyeType  string  `json:"dyeType"`
		IkatType string  `json:"ikatType"`
	}

	// Bind JSON request body to struct
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	// Generate unique ID using UUID
	id := uuid.New().String()

	// Insert saree details into the database
	_, err := db.Exec(
		"INSERT INTO saree_details (id, material, price, in_date, weaver, dyeType, ikatType) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, request.Material, request.Price, request.InDate, request.Weaver, request.DyeType, request.IkatType,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error saving saree details"})
		log.Println(err)
		return
	}

	c.JSON(200, gin.H{"message": "Saree details saved successfully"})
}

func main() {
	// Load environment variables
	loadEnvVars()

	// Initialize database connection and create the database & table
	initDB()

	// Create a new Gin router
	r := gin.Default()

	// Define API endpoint
	r.POST("/api/sarees", saveSareeDetails)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	r.Run(":" + port)
}

