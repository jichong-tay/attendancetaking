package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	uuid "github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func route() {

	//routing for css
	http.Handle("/css/", http.StripPrefix("/css", http.FileServer(http.Dir("./css"))))
	http.HandleFunc("/", index)
	http.HandleFunc("/restricted", restricted)
	//http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/record", record)
	http.HandleFunc("/upload", uploadXML)
	http.HandleFunc("/import", importXML)
	http.HandleFunc("/export", exportXML)
	http.HandleFunc("/backup", backup)
	http.Handle("/favicon.ico", http.NotFoundHandler())

}

// backup is for saving the db
func backup(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if !myUser.Isadmin {
		http.Redirect(res, req, "/", http.StatusUnauthorized)
		return
	}
	datafile.Attendancelist = attendancedb
	//backupDB is to save the db to xml
	backupDB(filename, datafile)
	http.Redirect(res, req, "/restricted", http.StatusSeeOther)
}

// export database to xml
func exportXML(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if !myUser.Isadmin {
		http.Redirect(res, req, "/", http.StatusUnauthorized)
		return
	}
	datafile.Attendancelist = attendancedb
	xmlData := generateXMLData(datafile)

	res.Header().Set("Content-Disposition", "attachment; filename=datafile.xml")
	res.Header().Set("Content-Type", "application/xml")
	res.Write(xmlData)
}

// upload database from xml
func uploadXML(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if !myUser.Isadmin {
		http.Redirect(res, req, "/", http.StatusUnauthorized)
		return
	}
	//check to ensure method is post
	if req.Method != http.MethodPost {

		http.Redirect(res, req, "/restricted", http.StatusSeeOther)
		return
	}

	//parse input, type multipart/form-data, checking file size)
	req.Body = http.MaxBytesReader(res, req.Body, max_upload_size)
	if err := req.ParseMultipartForm(max_upload_size); err != nil {
		http.Error(res, fmt.Sprintf("The uploaded file is too big. Please choose an file less than %d mb \n %s \n", max_upload_size/1000, err.Error()), http.StatusBadRequest)
		return
	}

	//retreieve file from posted form-data
	file, fileHeader, err := req.FormFile("myFile")

	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	defer file.Close()

	log.Printf("Uploaded File: %+v\n", fileHeader)

	//write temporary file on our server

	dst, err := os.Create(fmt.Sprintf("./data/database%s", filepath.Ext(fileHeader.Filename)))
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	loadDB(filename, datafile)

	log.Printf("Upload successful.\n")
	http.Redirect(res, req, "/restricted", http.StatusSeeOther)
}

// index page to display attendance of user
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

// restricted page for admin users
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

// import function to route admin user to import page
func importXML(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if !myUser.Isadmin {
		http.Redirect(res, req, "/", http.StatusUnauthorized)
		return
	}

	if err := tpl.ExecuteTemplate(res, "import.gohtml", attendancedb); err != nil {
		log.Println(err)
	}
}

// login users
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

// logout users
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

// record attendance
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

// getUser that is login in the current session
func getUser(res http.ResponseWriter, req *http.Request) user {
	// get current session cookie
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		id := uuid.New()
		myCookie = &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}
	}
	http.SetCookie(res, myCookie)

	// if the user exists already, get user
	var myUser user
	if username, ok := mapSessions[myCookie.Value]; ok {
		myUser = mapUsers[username]
	}
	return myUser
}

// alreadyLoggedIn is to check if user is already logged in.
func alreadyLoggedIn(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := mapSessions[myCookie.Value]
	_, ok := mapUsers[username]
	return ok
}

// func signup(res http.ResponseWriter, req *http.Request) {
// 	if alreadyLoggedIn(req) {
// 		http.Redirect(res, req, "/", http.StatusSeeOther)
// 		return
// 	}
// 	var myUser user
// 	// process form submission
// 	if req.Method == http.MethodPost {
// 		// get form values
// 		username := req.FormValue("username")
// 		password := req.FormValue("password")
// 		if username != "" {
// 			// check if username exist/ taken
// 			if _, ok := mapUsers[username]; ok {
// 				http.Error(res, "Username already taken", http.StatusForbidden)
// 				return
// 			}
// 			// create session
// 			id := uuid.New()
// 			myCookie := &http.Cookie{
// 				Name:  "myCookie",
// 				Value: id.String(),
// 			}
// 			http.SetCookie(res, myCookie)
// 			mapSessions[myCookie.Value] = username

// 			bPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
// 			if err != nil {
// 				http.Error(res, "Internal server error", http.StatusInternalServerError)
// 				return
// 			}

// 			myUser = user{username, bPassword, false}
// 			mapUsers[username] = myUser
// 		}
// 		// redirect to main index
// 		http.Redirect(res, req, "/", http.StatusSeeOther)
// 		return
// 	}
// 	tpl.ExecuteTemplate(res, "signup.gohtml", myUser)
// }
