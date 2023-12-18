package main

import (
	"bytes"
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

func loadDB(filename string, datafile data) {
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

func backupDB(filename string, datafile data) {
	f, err := os.Create(filename)
	if nil != err {
		log.Fatal(err)
	}
	defer f.Close()

	xmlEncoder := xml.NewEncoder(f)
	xmlEncoder.Encode(&datafile)
}

func generateXMLData(datafile data) []byte {
	// Create a buffer to store the XML data
	buffer := &bytes.Buffer{}
	// Create an XML encoder using the buffer
	xmlEncoder := xml.NewEncoder(buffer)

	// Encode the datafile into XML
	if err := xmlEncoder.Encode(&datafile); err != nil {
		log.Fatal(err)
	}

	// Return the byte slice containing the XML data
	return buffer.Bytes()
}
