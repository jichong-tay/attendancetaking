package main

import (
	"encoding/xml"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	uuid "github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func route() {

	http.Handle("/css/", http.StripPrefix("/css", http.FileServer(http.Dir("./css"))))
	http.HandleFunc("/", index)
	http.HandleFunc("/restricted", restricted)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/record", record)
	http.HandleFunc("/upload", uploadFile)
	http.Handle("/favicon.ico", http.NotFoundHandler())

}

func uploadFile(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(res, "Uploading File")
	//1. parse input, type multipart/form-data
	//2. retreieve file from posted form-data
	//3. write temporary file on our server
	//4. return whether or not this is successful

}

func readDBv2(filename string, datafile data) {
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

func index(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	userAttendance := userAttendance{}
	userAttendance.User = myUser
	userAttendance.AlreadyLoggedIn = alreadyLoggedIn(req)

	//Display list of attendenace for current user
	for _, attendance := range attendancedb {
		if attendance.Username == myUser.Username {
			userAttendance.Attendance = append(userAttendance.Attendance, attendance)
		}
	}

	if err := tpl.ExecuteTemplate(res, "index.gohtml", userAttendance); err != nil {
		log.Println(err)
	}

}

func restricted(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if !myUser.Isadmin {
		http.Redirect(res, req, "/", http.StatusUnauthorized)
		return
	}

	if err := tpl.ExecuteTemplate(res, "restricted.gohtml", attendancedb); err != nil {
		log.Println(err)
	}
}

func signup(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	var myUser user
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username != "" {
			// check if username exist/ taken
			if _, ok := mapUsers[username]; ok {
				http.Error(res, "Username already taken", http.StatusForbidden)
				return
			}
			// create session
			id := uuid.New()
			myCookie := &http.Cookie{
				Name:  "myCookie",
				Value: id.String(),
			}
			http.SetCookie(res, myCookie)
			mapSessions[myCookie.Value] = username

			bPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				http.Error(res, "Internal server error", http.StatusInternalServerError)
				return
			}

			myUser = user{username, bPassword, false}
			mapUsers[username] = myUser
		}
		// redirect to main index
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "signup.gohtml", myUser)
}

func login(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		// check if user exist with username
		myUser, ok := mapUsers[username]
		if !ok {
			http.Error(res, "Username and/or password do not match", http.StatusUnauthorized)
			return
		}
		// Matching of password entered
		err := bcrypt.CompareHashAndPassword(myUser.Password, []byte(password))
		if err != nil {
			http.Error(res, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// create session
		id := uuid.New()
		myCookie := &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}
		http.SetCookie(res, myCookie)
		mapSessions[myCookie.Value] = username
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(res, "login.gohtml", nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myCookie, _ := req.Cookie("myCookie")
	// delete the session
	delete(mapSessions, myCookie.Value)
	// remove the cookie
	myCookie = &http.Cookie{
		Name:   "myCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, myCookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func record(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	//process form submission
	if req.Method == http.MethodPost {
		myUser := getUser(res, req)
		// check if user exist with username
		myUserAttendance := attendance{
			Username: myUser.Username,
			Date:     time.Now(),
		}
		attendancedb = append(attendancedb, myUserAttendance)
		fmt.Println("Attendance recorded:", attendancedb)
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	// Handle other cases (GET request)
	// Redirect if already logged in
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
}
