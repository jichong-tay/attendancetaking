
**Readme**

**Cybersecurity**

1. Use of Go Template Engine (html/template)
    1. change the display of content according to context.
    2. escape the content correctly
2. Use of HTTP/TLS
    1. Use ```http.ListenAndServeTLS``` together with a ```key.pem``` and ```cert.pem```
3. Error Handling and Logging
    1. Use of ```log.Fatal```
4. Use of Hash to store user pasword
    1. bcrypt

---
***Default Configuration***

Default admin user is ```admin```

Default password is stored in ```.env``` file

create a ```database.xml``` at ```./data``` folder. 

xml file format for ```database.xml``` :

```
<data>
    <attendence>
        <username>user 1</username>
    </attendence>
        <attendence>
        <username>user 2</username>
    </attendence>
</data>
```
Put ```cert.pem``` and ```key.pem``` in the root directory.

---
_**Rapid Development of Attendance Taking Application using Templates and Go**_

```
Instructions

Minimal Requirement

Material covered in Networking in Go:
    - Net\Http
    - Templates
    - XML/ JSON
    - Cookies
    - Sessions using UUID

The application shall consist of the following roles
    - Admin
    - End Users / Participants

The application shall allow the user to do the following operations.
    - Login / Logout
    - Check in Attendance
    - Upon taking attendance, the application shall record the time and date of the attendance.

The minimal documentation shall make use of Go Docs.
Documentation shall be clear/ simple / consistent in style and content.
The application shall allow uploading of list of students / participants prior to starting by the admin.

The list of students to be loaded shall be in either of the following format: (Options)
    - XML
    - JSON
    - txt
    - CSV

The application shall store the list of users as map or struct.
The application shall run on 127.0.0.1:5332
The admin shall trigger the creation of the attendance list.

The application shall output either one of the following: (Options)
    - JSON file
    - XML file
    - CSV
    - Excel
    - PDF
    - .Docx
    - .txt

Additional Enhancements (Optional)

Additional enhancements will be up to the individual to add upon.
    - User Interface for ease of use
    - Advance mapping of users / data
    - Additional pages for navigation if any.
