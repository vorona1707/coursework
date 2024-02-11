package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"html/template"
)

type Post struct {
	gorm.Model

	Title   string
	Content string
}

type User struct {
	gorm.Model

	ID       uint
	Username string `gorm:"unique"`
	Password string
}

func main() {
	db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}
	err = db.AutoMigrate(&User{}, &Post{})
	if err != nil {
		fmt.Printf("Error migrating database: %v\n", err)
		return
	}

	var posts []*Post
	err = db.Find(&posts).Error
	if err != nil {
		fmt.Printf("Error getting users: %v\n", err)
		return
	}

	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("static/index.template")
		if err != nil {
			fmt.Printf("Error parsing template: %v\n", err)
			return
		}
		err = tmpl.Execute(w, posts)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}
	})

	router.HandleFunc("/create_post", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			fmt.Printf("Error parsing form: %v\n", err)
			return
		}

		title := r.FormValue("title")
		content := r.FormValue("content")

		post := &Post{
			Title:   title,
			Content: content,
		}

		err = db.Create(post).Error
		if err != nil {
			fmt.Printf("Error creating post: %v\n", err)
			return
		}
		posts = append(posts, post)

		http.Redirect(w, r, "/", http.StatusFound)
	})

	http.ListenAndServe(":8080", router)
}
