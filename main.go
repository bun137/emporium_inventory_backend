package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
)

var (
	db        *sql.DB
	jwtSecret []byte
)

// Load environment variables
func loadEnvVars() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatal("JWT_SECRET is not set in .env file")
	}
}

// Middleware to enable CORS
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

// Middleware to verify JWT
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(401, gin.H{"error": "Authorization token required"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("userId", claims["userId"].(string))
		c.Next()
	}
}

// Initialize the database
func initDB() {
	var err error
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	connStr := fmt.Sprintf("%s:%s@tcp(%s)/", dbUser, dbPassword, dbHost)
	db, err = sql.Open("mysql", connStr)
	if err != nil {
		log.Fatal("Error connecting to MySQL:", err)
	}

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", dbName))
	if err != nil {
		log.Fatal("Error creating database:", err)
	}

	connStr = fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err = sql.Open("mysql", connStr)
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging database:", err)
	}

	createTables()
}

// Create necessary tables
func createTables() {
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255),
		email VARCHAR(255) UNIQUE,
		password VARCHAR(255),
		role VARCHAR(50) DEFAULT 'user',
		isApproved BOOLEAN DEFAULT FALSE
	);`
	_, err := db.Exec(usersTable)
	if err != nil {
		log.Fatal("Error creating users table:", err)
	}
}

// User registration handler
func registerUser(c *gin.Context) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	userID := uuid.New().String()

	_, err := db.Exec(
		"INSERT INTO users (id, name, email, password, isApproved) VALUES (?, ?, ?, ?, ?)",
		userID, req.Name, req.Email, hashedPassword, false, // isApproved = false
	)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error creating user"})
		return
	}

	c.JSON(200, gin.H{"message": "User registered successfully. Awaiting admin approval."})
}

// User login handler
func loginHandler(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	var user struct {
		ID         string
		Password   string
		Role       string
		IsApproved bool
	}

	// Fetch user details from the database
	err := db.QueryRow("SELECT id, password, role, isApproved FROM users WHERE email = ?", req.Email).
		Scan(&user.ID, &user.Password, &user.Role, &user.IsApproved)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid email or password"})
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid email or password"})
		return
	}

	// Include isApproved in the token payload
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":     user.ID,
		"role":       user.Role,
		"isApproved": user.IsApproved, // Add this field
		"exp":        time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(200, gin.H{"message": "Login successful", "token": tokenString})
}

// List unapproved users
func listUnapprovedUsers(c *gin.Context) {
	rows, err := db.Query("SELECT id, name, email FROM users WHERE isApproved = ?", false)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error fetching unapproved users"})
		return
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id, name, email string
		if err := rows.Scan(&id, &name, &email); err != nil {
			c.JSON(500, gin.H{"error": "Error scanning user data"})
			return
		}
		users = append(users, map[string]interface{}{
			"id":    id,
			"name":  name,
			"email": email,
		})
	}
	c.JSON(200, gin.H{"users": users})
}

// Approve user
func approveUser(c *gin.Context) {
	var req struct {
		UserID string `json:"userId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}
	_, err := db.Exec("UPDATE users SET isApproved = TRUE WHERE id = ?", req.UserID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error approving user"})
		return
	}
	c.JSON(200, gin.H{"message": "User approved successfully"})
}

func validateTokenHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(401, gin.H{"error": "Authorization token required"})
		return
	}

	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(401, gin.H{"error": "Invalid token claims"})
		return
	}

	// Ensure isApproved is returned
	c.JSON(200, gin.H{
		"userId":     claims["userId"],
		"role":       claims["role"],
		"isApproved": claims["isApproved"],
	})
}


func main() {
	loadEnvVars()
	initDB()

	r := gin.Default()
	r.Use(corsMiddleware())

	r.POST("/api/register", registerUser)
	r.POST("/api/login", loginHandler)
	r.GET("/api/admin/users", authMiddleware(), listUnapprovedUsers)
	r.POST("/api/admin/approve-user", authMiddleware(), approveUser)
	r.GET("/api/validate-token", validateTokenHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	r.Run(":" + port)
}
