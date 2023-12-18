package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

const (
	filename        = "data/database.xml"
	max_upload_size = 1 << 20 //1 mb
)

func init() {

	//creation of admin user
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	password := os.Getenv("PASSWORD")
	bPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)

	mapUsers["admin"] = user{
		Username: "admin",
		Password: bPassword,
		Isadmin:  true,
	}

}
func main() {

	route()

	log.Println("server started")

	loadDB(filename, datafile)

	log.Fatal(http.ListenAndServeTLS(":5332", "cert.pem", "key.pem", nil))
}
