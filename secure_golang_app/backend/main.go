package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"html"
	"net/http"
	_ "secure_golang_app/docs" // Nome do módulo no go.mod
	"time"
)

// @title Secure Golang API
// @version 1.0
// @description This is a sample API with JWT authentication and XSS protection.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @BasePath /

var jwtKey = []byte("65a8e27d8879283831b664bd8b7f0ad4")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// @Summary Login
// @Description Perform login and get JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body Credentials true "Credentials"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /login [post]
func login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Simulating authentication
	if creds.Username != "user" || creds.Password != "password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("Authorization")

		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// @Summary Secure Data
// @Description Get secure data (protected route)
// @Tags data
// @Security ApiKeyAuth
// @Success 200 {object} map[string]string
// @Router /secure/data [get]
func secureData(c *gin.Context) {
	username := c.MustGet("username").(string)
	// Escape the username to prevent XSS
	safeUsername := html.EscapeString(username)
	c.JSON(http.StatusOK, gin.H{"message": "Hello, " + safeUsername})
}

func main() {
	r := gin.Default()

	// Configuração personalizada do CORS para aceitar apenas localhost
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"http://localhost:3000"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}))

	// Swagger route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Rotas de autenticação e proteção
	r.POST("/login", login)
	authorized := r.Group("/secure")
	authorized.Use(authMiddleware())
	{
		authorized.GET("/data", secureData)
	}

	r.Run(":8080")
}
