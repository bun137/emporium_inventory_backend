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
        // Set allowed origin to the specific frontend URL
        origin := c.Request.Header.Get("Origin")
        if origin == "http://localhost:5173" {
            c.Header("Access-Control-Allow-Origin", origin)
        }
        
        c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, Cache-Control")
        c.Header("Access-Control-Allow-Credentials", "true")
        
        // Handle preflight requests
        if c.Request.Method == "OPTIONS" {
            c.Header("Access-Control-Max-Age", "86400") // 24 hours
            c.Status(204)
            c.Abort()
            return
        }
        
        c.Next()
    }
}

func authMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        log.Printf("Received Authorization header: %s", tokenString) // Debug log

        if tokenString == "" {
            log.Printf("No Authorization header found") // Debug log
            c.JSON(401, gin.H{"error": "Authorization token required"})
            c.Abort()
            return
        }

        // Check if the token starts with "Bearer "
        if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
            log.Printf("Token doesn't start with 'Bearer '") // Debug log
            c.JSON(401, gin.H{"error": "Invalid token format"})
            c.Abort()
            return
        }

        // Parse the JWT
        token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                log.Printf("Unexpected signing method: %v", token.Header["alg"]) // Debug log
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtSecret, nil
        })

        if err != nil {
            log.Printf("Error parsing token: %v", err) // Debug log
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        if !token.Valid {
            log.Printf("Token is invalid") // Debug log
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Extract claims
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            log.Printf("Could not extract claims from token") // Debug log
            c.JSON(401, gin.H{"error": "Invalid token claims"})
            c.Abort()
            return
        }

        log.Printf("Token claims: %+v", claims) // Debug log

        userID, userOk := claims["userId"].(string)
        if !userOk || userID == "" {
            log.Printf("Invalid or missing userId in claims") // Debug log
            c.JSON(403, gin.H{"error": "Invalid or missing userId in token"})
            c.Abort()
            return
        }

        // Check role if requiredRole is specified
        if requiredRole != "" {
            var exists bool
            err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND role = ?)", userID, requiredRole).Scan(&exists)
            if err != nil {
                log.Printf("Error checking user role: %v", err) // Debug log
                c.JSON(500, gin.H{"error": "Error checking user role"})
                c.Abort()
                return
            }
            if !exists {
                log.Printf("User %s does not have required role %s", userID, requiredRole) // Debug log
                c.JSON(403, gin.H{"error": "Access denied"})
                c.Abort()
                return
            }
        }

        c.Set("userId", userID)
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
	createSareesTable()
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
		// Create an index on the 'id' column for fast lookups
	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_user_id ON users (id);")
	if err != nil {
		log.Fatal("Error creating index on users table:", err)
	}

}

func createSareesTable() {
    sareesTable := `
    CREATE TABLE IF NOT EXISTS sarees (
        id VARCHAR(36) PRIMARY KEY,
        material VARCHAR(255),
        price DECIMAL(10, 2),
        in_date DATE,
        weaver VARCHAR(255) NULL,
        dye_type VARCHAR(255),
        ikat_type VARCHAR(255)
    );`
    _, err := db.Exec(sareesTable)
    if err != nil {
        log.Fatal("Error creating sarees table:", err)
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
    err := db.QueryRow(
        "SELECT id, password, role, isApproved FROM users WHERE email = ?",
        req.Email,
    ).Scan(&user.ID, &user.Password, &user.Role, &user.IsApproved)
    
    if err != nil {
        log.Printf("Login failed for email %s: %v", req.Email, err)
        c.JSON(401, gin.H{"error": "Invalid email or password"})
        return
    }

    // Verify password
    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
    if err != nil {
        log.Printf("Password verification failed for user %s", user.ID)
        c.JSON(401, gin.H{"error": "Invalid email or password"})
        return
    }

    // Create the token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "userId": user.ID,
        "role":   user.Role,
        "exp":    time.Now().Add(24 * time.Hour).Unix(),
    })

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        log.Printf("Error generating token: %v", err)
        c.JSON(500, gin.H{"error": "Error generating token"})
        return
    }

    log.Printf("Successful login for user %s with role %s", user.ID, user.Role)

    c.JSON(200, gin.H{
        "message": "Login successful",
        "token":   tokenString,
        "user": gin.H{
            "id":         user.ID,
            "role":      user.Role,
            "isApproved": user.IsApproved,
        },
    })
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

func listApprovedUsers(c *gin.Context){
    rows, err := db.Query("SELECT id, name, email FROM users WHERE isApproved = ?", true)
    if err != nil {
        c.JSON(500, gin.H{"error": "Error fetching approved users"})
        return
    }
    defer rows.Close()

    var users []map[string]interface{}
    for rows.Next() {
        var id, name, email string
        if err := rows.Scan(&id, &name, &email); err != nil{
            c.JSON(500, gin.H{"error": "Error scanning user data"})
            return
        }
        users = append(users, map[string]interface{}{
            "id": id,
            "name": name,
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

    userID := claims["userId"].(string)
    var isApproved sql.NullBool
    var role string

    // Fetch approval status and role
    err = db.QueryRow("SELECT isApproved, role FROM users WHERE id = ?", userID).Scan(&isApproved, &role)
    if err != nil {
        log.Printf("Error fetching user data: %v", err)
        c.JSON(500, gin.H{"error": "Error fetching user data"})
        return
    }

    // Convert sql.NullBool to a standard boolean
    approvalStatus := false
    if isApproved.Valid {
        approvalStatus = isApproved.Bool
    }

    c.JSON(200, gin.H{
        "userId":     userID,
        "role":       role,
        "isApproved": approvalStatus,
    })
}

func createSaree(c *gin.Context) {
    var request struct {
        Material string  `json:"material"`
        Price    float64 `json:"price"`
        InDate   string  `json:"inDate"`
        Weaver   *string `json:"weaver"` // Nullable
        DyeType  string  `json:"dyeType"`
        IkatType string  `json:"ikatType"`
    }

    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(400, gin.H{"error": "Invalid request data"})
        return
    }

    // Generate a new UUID for the saree
    sareeID := uuid.New().String()

    // Insert the saree into the database
    _, err := db.Exec(
        "INSERT INTO sarees (id, material, price, in_date, weaver, dye_type, ikat_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
        sareeID, request.Material, request.Price, request.InDate, request.Weaver, request.DyeType, request.IkatType,
    )
    if err != nil {
        c.JSON(500, gin.H{"error": "Error creating saree"})
        return
    }

    c.JSON(200, gin.H{"message": "Saree created successfully", "id": sareeID})
}

// FetchSarees handler
func fetchSarees(c *gin.Context) {
    rows, err := db.Query("SELECT id, material, price, in_date, weaver, dye_type, ikat_type FROM sarees")
    if err != nil {
        c.JSON(500, gin.H{"error": "Error fetching sarees"})
        return
    }
    defer rows.Close()

    var sarees []map[string]interface{}
    for rows.Next() {
        var id, material, inDate, dyeType, ikatType string
        var price float64
        var weaver *string
        if err := rows.Scan(&id, &material, &price, &inDate, &weaver, &dyeType, &ikatType); err != nil {
            c.JSON(500, gin.H{"error": "Error scanning saree data"})
            return
        }
        sarees = append(sarees, map[string]interface{}{
            "id":       id,
            "material": material,
            "price":    price,
            "inDate":   inDate,
            "weaver":   weaver,
            "dyeType":  dyeType,
            "ikatType": ikatType,
        })
    }

    c.JSON(200, gin.H{"sarees": sarees})
}

// Revoke user access handler
func revokeUser(c *gin.Context) {
	var req struct {
		UserID string `json:"userId"`
	}

	// Bind JSON input to the request struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	// Check if the user exists and is currently approved
	var isApproved bool
	err := db.QueryRow("SELECT isApproved FROM users WHERE id = ?", req.UserID).Scan(&isApproved)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(404, gin.H{"error": "User not found"})
		} else {
			log.Printf("Error fetching user data: %v", err)
			c.JSON(500, gin.H{"error": "Error fetching user data"})
		}
		return
	}

	if !isApproved {
		c.JSON(400, gin.H{"error": "User is already unapproved"})
		return
	}

	// Revoke the user's approval
	_, err = db.Exec("UPDATE users SET isApproved = FALSE WHERE id = ?", req.UserID)
	if err != nil {
		log.Printf("Error revoking user access: %v", err)
		c.JSON(500, gin.H{"error": "Error revoking user access"})
		return
	}

	c.JSON(200, gin.H{"message": "User access revoked successfully"})
}


func main() {
	loadEnvVars()
	initDB()

	r := gin.Default()
	r.Use(corsMiddleware())

	// Public Routes
	r.POST("/api/register", registerUser)
	r.POST("/api/login", loginHandler)

	// Admin Protected Routes
	adminGroup := r.Group("/api/admin")
	adminGroup.Use(authMiddleware("admin"))
	{
		adminGroup.GET("/users", listUnapprovedUsers)
		adminGroup.POST("/approve-user", approveUser)
		adminGroup.POST("/revoke-user", revokeUser) // New Route for Revoking Users
		adminGroup.GET("/approvedUsers", listApprovedUsers)
	}

	// Sarees Routes
	sareesGroup := r.Group("/api/sarees")
	sareesGroup.Use(authMiddleware(""))
	{
		sareesGroup.GET("", fetchSarees)
		sareesGroup.POST("", createSaree)
	}

	// Token Validation
	r.GET("/api/validate-token", authMiddleware(""), validateTokenHandler)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	r.Run(":" + port)
}
