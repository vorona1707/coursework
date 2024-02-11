package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"text/template"

	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Product struct {
	gorm.Model

	Name        string
	Price       int
	Weight      int
	Description string
	Size        string
}

func main() {

	mux := mux.NewRouter()

	db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}

	err = db.AutoMigrate(&Product{})
	if err != nil {
		fmt.Printf("Error migrating database: %v\n", err)
		return
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("static/products.tmpl")
		if err != nil {
			fmt.Printf("Error parsing template: %v\n", err)
			return
		}

		var products []*Product
		err = db.Find(&products).Error
		if err != nil {
			fmt.Printf("Говно вопрос: %v\n", err)
			return
		}

		err = tmpl.Execute(w, products)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return

		}
	})

	mux.HandleFunc("/create_product", func(w http.ResponseWriter, r *http.Request) {

		err := r.ParseForm()
		if err != nil {
			fmt.Printf("Ошибка формы: %v\n", err)
			return
		}

		name := r.FormValue("name")
		price := r.FormValue("price")
		weight := r.FormValue("weight")
		description := r.FormValue("description")
		size := r.FormValue("size")

		if name == "" {
			fmt.Printf("ты что наделал сука \n")
			return
		}

		if description == "" {
			fmt.Printf("ты что наделал сука \n")
			return
		}

		if size == "" {
			fmt.Printf("ты что наделал сука \n")
			return
		}

		price_int, err := strconv.Atoi(price)
		if err != nil {
			fmt.Printf("говно ситуация \n")
			return
		}

		weight_int, err := strconv.Atoi(weight)
		if err != nil {
			fmt.Printf("говно конечно \n")
			return
		}

		product := &Product{
			Name:        name,
			Price:       price_int,
			Weight:      weight_int,
			Description: description,
			Size:        size,
		}

		err = db.Create(product).Error
		if err != nil {
			fmt.Printf("Ошибка \n")
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal(err)
	}
}
