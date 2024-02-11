package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	//"strconv"
	"text/template"

	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model

	ID       uint
	Name     string
	Surname  string
	Password string
	Email    string
}

func main() {

	mux := mux.NewRouter()

	db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}

	err = db.AutoMigrate(&User{})
	if err != nil {
		fmt.Printf("Error migrating database: %v\n", err)
		return
	}

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("static/reg.tmpl")
		if err != nil {
			fmt.Printf("Error parsing template: %v\n", err)
			return
		}

		var users []*User
		err = db.Find(&users).Error
		if err != nil {
			fmt.Printf("Говно вопрос: %v\n", err)
			return
		}

		err = tmpl.Execute(w, users)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return

		}
	})

	mux.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	mux.HandleFunc("/reg", func(w http.ResponseWriter, r *http.Request) {

		err := r.ParseForm()
		if err != nil {
			fmt.Printf("Ошибка формы: %v\n", err)
			return
		}

		name := r.FormValue("name")
		surname := r.FormValue("surname")
		password := r.FormValue("password")
		email := r.FormValue("email")
		//weight := r.FormValue("weight")
		//description := r.FormValue("description")
		//size := r.FormValue("size")

		if name == "" {
			fmt.Printf("ошибка имени \n")
			return
		}

		if surname == "" {
			fmt.Printf("ошибка фамилии \n")
			return
		}

		if email == "" {
			fmt.Printf("ошибка email \n")
			return
		}

		//price_int, err := strconv.Atoi(price)

		//weight_int, err := strconv.Atoi(weight)
		//if err != nil {
		//	fmt.Printf("говно конечно \n")
		//	return
		//}

		user := &User{
			Name:     name,
			Surname:  surname,
			Password: password,
			Email:    email,
		}

		err = db.Create(user).Error
		if err != nil {
			fmt.Printf("Ошибка \n")
			return
		}
		http.Redirect(w, r, "/register", http.StatusFound)

	})

	mux.HandleFunc("/deleteform", func(w http.ResponseWriter, r *http.Request) {

		tmpl, err := template.ParseFiles("static/deldb.tmpl")
		if err != nil {
			fmt.Printf("Error parsing template: %v\n", err)
			return
		}

		var users []*User

		err = db.Find(&users).Error
		if err != nil {
			fmt.Printf("Говно вопрос: %v\n", err)
			return
		}

		err = tmpl.Execute(w, users)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}
	})

	mux.HandleFunc("/delid", func(w http.ResponseWriter, r *http.Request) {

		err := r.ParseForm()
		if err != nil {
			fmt.Printf("Ошибка формы: %v\n", err)
			return
		}

		var users []*User

		err = db.Find(&users).Error
		if err != nil {
			fmt.Printf("Говно вопрос: %v\n", err)
			return
		}

		deleteid := r.FormValue("deleteid")
		deleteid_int, err := strconv.Atoi(deleteid)

		err = db.Delete(&User{}, deleteid_int).Error
		if err != nil {
			fmt.Printf("Ошибка удаления \n")
			return
		}
		http.Redirect(w, r, "/deleteform", http.StatusFound)
	})

	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal(err)
	}
}
