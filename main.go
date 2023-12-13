package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

const (
	filename = "data/database.xml"
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

	// mapUsers["john"] = user{
	// 	Username: "john",
	// 	Password: bPassword,
	// 	Isadmin:  false,
	// }

	// attendancedb = append(attendancedb, attendance{"john", "mon"})
	// attendancedb = append(attendancedb, attendance{"john", "tues"})

}
func main() {

	route()
	log.Println("server started")

	readDB(filename, datafile)
	fmt.Println("main database:", datafile.Attendancelist)
	//writeDB(filename, datafile)
	http.ListenAndServe(":5221", nil)
}
