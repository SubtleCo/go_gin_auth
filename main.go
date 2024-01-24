package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	awsRegion   = "us-east-2"
	awsEndpoint = "http://localhost:8000"
)

var (
	jwtKey = []byte("my_secret_key")
	tokens []string
)

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func main() {
	r := gin.Default()
	db := createDynamoDBClient()

	r.POST("/register", func(c *gin.Context) {
		var user struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		hashedPassword, err := hashPassword(user.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Save user in DB
		if err := saveUser(user.Email, string(hashedPassword), db); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully. Welcome!"})
	})

	r.POST("/login", func(c *gin.Context) {
		var loginDetails struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginDetails); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := getUser(loginDetails.Email, db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
			return
		}

		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No user by that email found"})
		}

		if !checkPasswordHash(loginDetails.Password, user.PasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid login credentials"})
			return
		}

		token, err := generateJTW(user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	})

	r.GET("/resource", func(c *gin.Context) {
		bearerToken := c.Request.Header.Get("Authorization")

		// Check for token
		if bearerToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "no auth header provided",
			})
			return
		}
		reqToken := strings.Split(bearerToken, " ")[1]
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(reqToken, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "unauthorized (invalid signature)",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "bad request",
			})
			return
		}
		if !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": "protected resource data",
		})
	})
	r.Run()
}

func generateJTW(email string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtKey)
}

// Salt and hash the password with bcrypt. The salt is stored in the hashed password, ready to be
// decoded with checkPasswordHash
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10) // 10 is the min recommended cost
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func createDynamoDBClient() *dynamodb.DynamoDB {
	// Setup the AWS session
	sess := session.Must(session.NewSession(&aws.Config{
		Region:   aws.String(awsRegion),
		Endpoint: aws.String(awsEndpoint),
	}))

	// create DynamoDB client
	return dynamodb.New(sess)
}

type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"passwordHash"`
}

func saveUser(email, hashedPassword string, db *dynamodb.DynamoDB) error {
	input := &dynamodb.PutItemInput{
		TableName: aws.String("Users"),
		Item: map[string]*dynamodb.AttributeValue{
			"Email": {
				S: aws.String(email),
			},
			"PasswordHash": {
				S: aws.String(hashedPassword),
			},
		},
	}

	_, err := db.PutItem(input)
	return err
}

func getUser(email string, db *dynamodb.DynamoDB) (*User, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("Users"),
		Key: map[string]*dynamodb.AttributeValue{
			"Email": {
				S: aws.String(email),
			},
		},
	}

	result, err := db.GetItem(input)
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, nil
	}

	var user User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
