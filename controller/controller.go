package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"rbacCustom/dbops"
	"rbacCustom/models"
	"rbacCustom/utils"
)

var err error

func Signup(w http.ResponseWriter, r *http.Request) {

	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckAdmin()
	if n > 0 {
		log.Println("admin already registered")
		w.Write([]byte("admin already registered"))
	}

	member.Password, err = utils.HashPassword(member.Password)
	if err != nil {
		log.Println("password hashing", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	// if n == 0 {
	// member.Privilage = "owner"
	// } else {
	// 	member.Privilage = "member"
	// }

	_, err = dbops.InsertUser(&member)
	if err != nil {
		log.Println("signing up user", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	w.Write([]byte("User can log in now"))
}

func Signin(w http.ResponseWriter, r *http.Request) {

	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckUser(member.Username)
	if n < 1 {
		log.Println("User not registered")
		w.Write([]byte("User not registered"))
	}

	user, err := dbops.FetchUser(member.Username)
	if err != nil {
		log.Println("FetchUser user", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	ok := utils.CheckPasswordHash(member.Password, user[0].Password)
	if !ok {
		log.Println("Password is wrong")
		w.Write([]byte("Password is wrong"))
	}
	token, err := utils.CreateToken(user[0])
	if !ok {
		log.Println("CreateToken error", err)
		w.Write([]byte("CreateToken error" + err.Error()))
	}

	user[0].Token = token

	json.NewEncoder(w).Encode(user[0])
}
