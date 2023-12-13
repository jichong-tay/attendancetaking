package main

import (
	"encoding/xml"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var mapUsers = map[string]user{}
var attendancedb []attendance
var mapSessions = map[string]string{}
var datafile = data{}

type data struct {
	XMLName        xml.Name     `xml:"data"`
	Attendancelist []attendance `xml:"attendence"`
}

type user struct {
	Username string
	Password []byte
	Isadmin  bool
}

type attendance struct {
	Username string    `xml:"username"`
	Date     time.Time `xml:"date,omitempty"`
}

type userAttendance struct {
	XMLName         xml.Name
	User            user
	Attendance      []attendance
	AlreadyLoggedIn bool
}

func readDB(filename string, datafile data) {
	f, err := os.Open(filename)
	if nil != err {
		log.Fatal(err)
	}
	defer f.Close()

	decoder := xml.NewDecoder(f)
	decoder.Decode(&datafile)
	attendancedb = datafile.Attendancelist

	//godotenv to load environment file
	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	//default password get from environment file
	password := os.Getenv("PASSWORD")
	bPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)

	for _, v := range attendancedb {
		mapUsers[v.Username] = user{
			Username: v.Username,
			Password: bPassword,
			Isadmin:  false,
		}

	}
}

func writeDB(filename string, datafile data) {
	f, err := os.Create(filename)
	if nil != err {
		log.Fatal(err)
	}
	defer f.Close()

	xmlEncoder := xml.NewEncoder(f)
	xmlEncoder.Encode(&datafile)
}
