package main

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- MODELE ---
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Name     string `gorm:"not null"`
	Email    string `gorm:"unique;not null"`
	Phone    string `gorm:"not null"`
	Password string `gorm:"not null"`
}

type Car struct {
	ID     uint   `gorm:"primaryKey"`
	UserID uint   `gorm:"unique;not null"`
	Brand  string `json:"brand"`
	Model  string `json:"model"`
	Plate  string `json:"plate"`
}

type DriverDocument struct {
	ID         uint      `gorm:"primaryKey"`
	UserID     uint      `gorm:"not null"`
	DocType    string    `gorm:"not null"`
	Status     string    `gorm:"default:'necesita'"`
	Value      string    `json:"value"`
	ExpiryDate string    `json:"expiry_date"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type AdminFullData struct {
	User User             `json:"user"`
	Car  Car              `json:"car"`
	Docs []DriverDocument `json:"docs"`
}

var db *gorm.DB
var jwtKey = []byte("cheia_mea_secreta_premium_drive_2026")

var allDocTypes = []string{
	"Poza Profil", "Buletin (CI)", "Permis de Conducere", "Atestat Profesional",
	"Cazier Judiciar", "Declarație proprie răspundere", "Asigurare RCA",
	"Certificat ITP", "Asigurare Bagaje", "Copie Conformă", "Insignă / Ecusoane",
}

// --- MIDDLEWARE PENTRU CORS (NECESAR PENTRU WEB) ---
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func main() {
	// Folosim variabila de mediu DB_URL dacă există, altfel fallback la DSN-ul tău
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		dsn = "postgresql://postgres:QYTgwJSzJJroDDwS@db.uzhyfmzhtaywdywgppfv.supabase.co:5432/postgres"
	}
	
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Eroare conexiune!")
	}

	db.AutoMigrate(&User{}, &Car{}, &DriverDocument{})

	r := gin.Default()

	// APLICĂM CORS ȘI ACTIVĂM SERVIREA FIȘIERELOR
	r.Use(CORSMiddleware())
	r.Static("/uploads", "./uploads")

	r.POST("/register", func(c *gin.Context) {
		var input struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Phone    string `json:"phone"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Date invalide"})
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
		newUser := User{
			Name:     strings.Title(strings.ToLower(input.Name)),
			Email:    input.Email,
			Phone:    input.Phone,
			Password: string(hashedPassword),
		}

		if err := db.Create(&newUser).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Email existent!"})
			return
		}

		for _, docName := range allDocTypes {
			db.Create(&DriverDocument{
				UserID:  newUser.ID,
				DocType: docName,
				Status:  "necesita",
			})
		}
		c.JSON(http.StatusOK, gin.H{"message": "Utilizator creat!"})
	})

	r.POST("/login", func(c *gin.Context) {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Date invalide"})
			return
		}
		var user User
		if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Date incorecte"})
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": user.ID,
			"exp":     time.Now().Add(time.Hour * 72).Unix(),
		})
		tokenString, _ := token.SignedString(jwtKey)
		c.JSON(http.StatusOK, gin.H{"token": tokenString, "user_id": user.ID, "name": user.Name})
	})

	r.GET("/get-car/:userid", func(c *gin.Context) {
		userID := c.Param("userid")
		var car Car
		if err := db.Where("user_id = ?", userID).First(&car).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"brand": "", "model": "", "plate": ""})
			return
		}
		c.JSON(http.StatusOK, car)
	})

	r.POST("/save-car", func(c *gin.Context) {
		var input struct {
			UserID uint   `json:"user_id"`
			Brand  string `json:"brand"`
			Model  string `json:"model"`
			Plate  string `json:"plate"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Date invalide"})
			return
		}
		var car Car
		result := db.Where("user_id = ?", input.UserID).First(&car)
		if result.Error != nil {
			db.Create(&Car{UserID: input.UserID, Brand: input.Brand, Model: input.Model, Plate: input.Plate})
		} else {
			db.Model(&car).Updates(Car{Brand: input.Brand, Model: input.Model, Plate: input.Plate})
		}
		c.JSON(http.StatusOK, gin.H{"message": "Masina salvata!"})
	})

	r.GET("/get-documents/:userid", func(c *gin.Context) {
		userID := c.Param("userid")
		var docs []DriverDocument
		db.Where("user_id = ?", userID).Find(&docs)
		c.JSON(http.StatusOK, docs)
	})

	r.POST("/save-document", func(c *gin.Context) {
		userID := c.PostForm("user_id")
		docType := c.PostForm("doc_type")
		expiryDate := c.PostForm("expiry_date")

		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Nu am primit fisierul"})
			return
		}

		os.MkdirAll("uploads", os.ModePerm)
		filePath := "uploads/" + userID + "_" + strings.ReplaceAll(docType, " ", "_") + ".jpg"
		
		if err := c.SaveUploadedFile(file, filePath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Eroare salvare"})
			return
		}

		db.Model(&DriverDocument{}).
			Where("user_id = ? AND doc_type = ?", userID, docType).
			Updates(map[string]interface{}{
				"value":       filePath,
				"expiry_date": expiryDate,
				"status":      "verificare",
				"updated_at":  time.Now(),
			})

		c.JSON(http.StatusOK, gin.H{"message": "Document trimis!"})
	})

	r.GET("/admin/full-dashboard", func(c *gin.Context) {
		var results []AdminFullData
		var users []User
		db.Find(&users)
		for _, user := range users {
			var car Car
			var docs []DriverDocument
			db.Where("user_id = ?", user.ID).First(&car)
			db.Where("user_id = ?", user.ID).Find(&docs)
			results = append(results, AdminFullData{User: user, Car: car, Docs: docs})
		}
		c.JSON(http.StatusOK, results)
	})

	r.POST("/admin/verify-doc", func(c *gin.Context) {
		var input struct {
			UserID  uint   `json:"user_id"`
			DocType string `json:"doc_type"`
			Status  string `json:"status"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Date invalide"})
			return
		}
		db.Model(&DriverDocument{}).Where("user_id = ? AND doc_type = ?", input.UserID, input.DocType).Update("status", input.Status)
		c.JSON(http.StatusOK, gin.H{"message": "Status actualizat!"})
	})

	// Setare port dinamic pentru Render
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}