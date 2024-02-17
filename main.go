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

type Product struct {
	gorm.Model

	ID          uint
	Name        string
	Price       int
	Description string
	//Image string

}

func main() {

	router := mux.NewRouter()

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

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

	err = db.AutoMigrate(&Product{})
	if err != nil {
		fmt.Printf("Error migrating database: %v\n", err)
		return
	}

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
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

	router.HandleFunc("/products/add/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("static/add_products.tmpl")
		if err != nil {
			fmt.Printf("Error parsing tempate: %n\n", err)
			return
		}

		var products []*Product
		err = db.Find(&products).Error
		if err != nil {
			fmt.Printf("Ошибка поиска юзера: %v\n", err)
			return
		}

		err = tmpl.Execute(w, products)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return

		}
	})

	router.HandleFunc("/products/add/create", func(w http.ResponseWriter, r *http.Request) {
    

		err := r.ParseForm()
		if err != nil {
			fmt.Printf("Ошибка формы: %v\n", err)
			return
		}

		name := r.FormValue("name")
		price := r.FormValue("price")
		description := r.FormValue("description")

		if name == "" {
			fmt.Printf("ошибка имени товара \n")
			return
		}

		if price == "" {
			fmt.Printf("ошибка поля цена \n")
			return
		}

		if description == "" {
			fmt.Printf("ошибка поля описание \n")
			return
		}

		price_int, err := strconv.Atoi(price)

		product := &Product{
			Name:        name,
			Price:       price_int,
			Description: description,
    }

    err = db.Create(product).Error
    if err != nil {
      fmt.Printf("db create product error %v \n",)
      return
    }

    http.Redirect(w, r, "/products/add/", http.StatusFound)
	})

	router.HandleFunc("/reg", func(w http.ResponseWriter, r *http.Request) {

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

		if password == "" {
			fmt.Printf("ошибка пароля \n")
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

	router.HandleFunc("/deleteform", func(w http.ResponseWriter, r *http.Request) {

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

		fmt.Printf("%+v \n", users)

		err = tmpl.Execute(w, users)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}
	})

	router.HandleFunc("/edit", func(w http.ResponseWriter, r *http.Request) {

		tmpl, err := template.ParseFiles("static/edit_users.tmpl")
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

		fmt.Printf("%+v \n", users)

		err = tmpl.Execute(w, users)

		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}

	})

	router.HandleFunc("/users/{id}/delete", func(w http.ResponseWriter, r *http.Request) {

		id := mux.Vars(r)["id"]
		idInt, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fmt.Printf("Error parsing id: %v\n", err)
			return
		}

		fmt.Printf("%+v /n", mux.Vars(r))

		err = db.Delete(&User{}, idInt).Error
		if err != nil {
			fmt.Printf("Ошибка удаления")
			return
		}

		var users []*User

		err = db.Find(&users).Error
		if err != nil {
			fmt.Printf("Говно вопрос: %v\n", err)
			return
		}

		http.Redirect(w, r, "/deleteform", http.StatusFound)
	})

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		tmpl, err := template.ParseFiles("static/index.tmpl")
		template.ParseFiles("static/output.css")
		if err != nil {
			fmt.Printf("Error parsing template: %v\n", err)
			return
		}

		err = tmpl.Execute(w, nil)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}

	})

	router.HandleFunc("/users/{id}/edit", func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		idInt, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fmt.Printf("id не число")
			return
		}

		err = r.ParseForm()
		if err != nil {
			fmt.Printf("Ошибка формы: %v\n", err)
			return
		}

		name := r.FormValue("name")
		surname := r.FormValue("surname")
		password := r.FormValue("password")
		email := r.FormValue("email")

		fmt.Printf("name: %v id: %v \n", name, idInt)

		var chelovek User

		err = db.Find(&chelovek, idInt).Error
		if err != nil {
			fmt.Printf("Говно вопрос: %v\n", err)
			return
		}

		fmt.Printf("chelovek: %+v", chelovek.Name)

		chelovek.Name = name
		chelovek.Surname = surname
		chelovek.Password = password
		chelovek.Email = email

		fmt.Printf("chelovek: %+v", chelovek.Surname)

		err = db.Save(chelovek).Error
		if err != nil {
			fmt.Printf("ошибка человека")
		}

		http.Redirect(w, r, "/edit", http.StatusFound)
	})

	router.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("static/signin.tmpl")
		if err != nil {
			fmt.Printf("Parsing error")
			return
		}

		err = tmpl.Execute(w, nil)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}
	})

	router.HandleFunc("/products/", func(w http.ResponseWriter, r *http.Request) {
		
    tmpl, err := template.ParseFiles("static/catalog.tmpl")
		if err != nil {
			fmt.Printf("Parsing error")
			return
		}
    
    var products []*Product
    

    err = db.Find(&products).Error
    if err != nil {
      fmt.Printf("Продукт не найден")
    }

		err = tmpl.Execute(w, products)
    if err != nil {
			fmt.Printf("Error executing template %v\n", err)
			return
		}
	})

	router.HandleFunc("/profile/{id}", func(w http.ResponseWriter, r *http.Request) {

		tmpl, err := template.ParseFiles("static/profile.tmpl")
		if err != nil {
			fmt.Printf("Error parsing template: %v\n", err)
			return
		}

		id := mux.Vars(r)["id"]
		idInt, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			fmt.Printf("id не число  2")
			return
		}

		var chelovek User

		err = db.Find(&chelovek, idInt).Error
		if err != nil {
			fmt.Printf("Ошибка не найден юзер")
		}

		err = tmpl.Execute(w, chelovek)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}

	})

	err = http.ListenAndServe(":8080", router)
	if err != nil {
		log.Fatal(err)
	}
}
