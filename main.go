package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"organic_store/models"
	"organic_store/services"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
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
	IsAdmin  bool
}

var db *gorm.DB
var err error
var tmpl *template.Template
var jwtKey = []byte("your_secret_key") // Используйте безопасный ключ

type Category struct {
	gorm.Model
	ID       uint `gorm:"primaryKey"`
	Name     string
	Products []Product
}

type Product struct {
	gorm.Model
	ID          uint `gorm:"primaryKey"`
	Name        string
	Price       float64
	Description string
	Image       string
	CategoryID  uint
}

type CartItem struct {
	ID        uint `gorm:"primaryKey"`
	ProductID uint
	UserID    uint
	Quantity  int
	Product   Product
}

type Article struct {
	gorm.Model
	Title       string
	Content     string
	Author      string
	PublishedAt time.Time
}

type AdminPanelData struct {
	Products   []Product
	Categories []Category
	Users      []User
	Articles   []Article
}

// Order представляет заказ пользователя
type Order struct {
	gorm.Model
	UserID     uint      // Идентификатор пользователя
	TotalPrice float64   // Общая стоимость заказа
	CreatedAt  time.Time // Время создания заказа
	Status     string
	OrderItems []OrderItem // Товары в заказе
}

// OrderItem представляет товар в заказе
type OrderItem struct {
	gorm.Model
	OrderID   uint    // Идентификатор заказа
	ProductID uint    // Идентификатор продукта
	Quantity  int     // Количество товара
	UnitPrice float64 // Цена за единицу
}

type OrderView struct {
	ID         uint
	TotalPrice float64
	CreatedAt  time.Time
	Status     string
	OrderItems []OrderItemView
}

type OrderItemView struct {
	ProductName string
	Quantity    int
	UnitPrice   float64
}

type contextKey string

var store = sessions.NewCookieStore([]byte("super-secret-key"))

func add(a, b float64) float64 {
	return a + b
}

func mul(a, b float64) float64 {
	return a * b
}

func prepareTemplate() (*template.Template, error) {
	funcMap := template.FuncMap{
		"add": add,
		"mul": mul,
	}

	// Загружаем и объединяем шаблоны с функциями
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/header.tmpl", "templates/footer.tmpl", "templates/user_cart.tmpl", "templates/user_navigation_cart.tmpl")
	if err != nil {
		return nil, fmt.Errorf("error parsing template files: %v", err)
	}
	return tmpl, nil
}

func GenerateToken(user User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	// Логирование для проверки значения IsAdmin перед созданием токена
	log.Printf("Generating token for user ID %d, isAdmin: %v", user.ID, user.IsAdmin)

	tokenClaims := jwt.MapClaims{
		"userID":    fmt.Sprint(user.ID),
		"expiresAt": expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			http.Error(w, "Authorization header format must be 'Bearer {token}'", http.StatusUnauthorized)
			return
		}

		tokenString := headerParts[1]
		claims := &jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			log.Printf("Error parsing token: %v", err) // Логирование ошибки
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Проверка на администратора или другие необходимые поля могут быть добавлены здесь
		isAdmin, ok := (*claims)["isAdmin"].(bool)
		if ok && isAdmin {
			// Добавляем данные в контекст, если нужно
			ctx := context.WithValue(r.Context(), "isAdmin", isAdmin)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		} else {
			log.Printf("Access denied: isAdmin=%v, ok=%v", isAdmin, ok) // Логирование состояния проверки
			http.Error(w, "Unauthorized - not an administrator", http.StatusUnauthorized)
		}
	})
}

func truncate(maxLen int, s string) string {
	if len(s) <= maxLen {
		return s
	}
	cutPos := maxLen
	for i := range s {
		if i > maxLen {
			break
		}
		cutPos = i
	}
	return s[:cutPos] + "..."
}

func main() {

	router := mux.NewRouter()

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	router.PathPrefix("/templates/").Handler(http.StripPrefix("/templates/", http.FileServer(http.Dir("templates"))))

	db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}

	err = db.AutoMigrate(&User{}, &Category{}, &models.Order{}, &models.OrderItem{}, &models.CartItem{}, &Product{}, &Article{})
	if err != nil {
		fmt.Printf("Error migrating database: %v\n", err)
		return
	}

	router.HandleFunc("/register/", func(w http.ResponseWriter, r *http.Request) {

		tmpl, err := template.ParseFiles("templates/register_form.tmpl", "templates/header.tmpl", "templates/footer.tmpl")
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

		err = tmpl.ExecuteTemplate(w, "register_form", nil)
		if err != nil {
			fmt.Printf("Error executing template: %v\n", err)
			return
		}
	})

	router.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		// Проверка статуса авторизации из контекста, установленного Middleware

		// Загрузка шаблонов
		tmpl := template.Must(template.ParseFiles("templates/header.tmpl", "templates/footer.tmpl", "templates/login_form.tmpl"))

		// Проверка наличия параметра ошибки
		error := r.URL.Query().Get("error")
		data := struct {
			Error bool
		}{
			Error: error == "1",
		}

		// Выполнение шаблона с данными
		if err := tmpl.ExecuteTemplate(w, "login_form", data); err != nil {
			http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		}
	})

	router.HandleFunc("/login/ok/", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var user User
		if err := db.Where("email = ? AND password = ?", email, password).First(&user).Error; err != nil {
			// Проверьте логин и пароль здесь
			http.Redirect(w, r, "/login/?error=1", http.StatusSeeOther)
			return
		}

		tokenString, err := GenerateToken(user) // Передача всего объекта user
		if err != nil {
			log.Printf("Error generating token: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Логируем, является ли пользователь администратором
		log.Printf("Token generated for %s (Admin: %t)", user.Email, user.IsAdmin)

		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Expires:  time.Now().Add(24 * time.Hour),
			MaxAge:   86400,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	router.HandleFunc("/user/navigation/cart", func(w http.ResponseWriter, r *http.Request) {
		userID, err := getSessionUserID(r)
		if err != nil {
			log.Println("Redirecting to login: ", err)
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}

		var user User
		if err := db.First(&user, userID).Error; err != nil {
			http.Error(w, "User not found: "+err.Error(), http.StatusNotFound)
			return
		}

		var cartItems []CartItem
		if result := db.Preload("Product").Where("user_id = ?", userID).Find(&cartItems); result.Error != nil {
			log.Printf("Failed to fetch cart items: %v\n", result.Error)
			http.Error(w, "Failed to fetch cart items", http.StatusInternalServerError)
			return
		}

		tmpl, err := prepareTemplate()
		if err != nil {
			log.Printf("Error preparing template: %v\n", err)
			http.Error(w, "Error preparing template", http.StatusInternalServerError)
			return
		}

		total := 0.0
		products := make([]struct {
			CartItemID uint // ID элемента корзины для использования в функциях удаления
			Product    Product
			Quantity   int
			SubTotal   float64
		}, len(cartItems))

		for i, item := range cartItems {
			products[i].CartItemID = item.ID // Сохраняем ID элемента корзины
			products[i].Product = item.Product
			products[i].Quantity = item.Quantity
			products[i].SubTotal = float64(item.Quantity) * item.Product.Price
			total += products[i].SubTotal
		}

		data := struct {
			Name     string
			LoggedIn bool
			Products []struct {
				CartItemID uint
				Product    Product
				Quantity   int
				SubTotal   float64
			}
			Total float64
		}{
			Name:     user.Name,
			LoggedIn: true,
			Products: products,
			Total:    total,
		}

		if err := tmpl.ExecuteTemplate(w, "user_navigation_cart", data); err != nil {
			log.Printf("Error executing template: %v\n", err)
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	router.HandleFunc("/user/navigation/orders", func(w http.ResponseWriter, r *http.Request) {
		userID, err := getSessionUserID(r)
		if err != nil {
			log.Println("Redirecting to login: ", err)
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}

		var orders []Order
		if err := db.Preload("OrderItems").Where("user_id = ?", userID).Find(&orders).Error; err != nil {
			http.Error(w, "Could not retrieve orders", http.StatusInternalServerError)
			return
		}

		var ordersView []OrderView

		for _, order := range orders {
			var orderView OrderView
			orderView.ID = order.ID
			orderView.CreatedAt = order.CreatedAt
			orderView.Status = order.Status

			totalPrice := 0.0
			for _, item := range order.OrderItems {
				var product Product
				if err := db.First(&product, item.ProductID).Error; err != nil {
					log.Printf("Error loading product for order item: %v", err)
					continue
				}
				orderItemView := OrderItemView{
					ProductName: product.Name,
					Quantity:    item.Quantity,
					UnitPrice:   item.UnitPrice,
				}
				orderView.OrderItems = append(orderView.OrderItems, orderItemView)
				totalPrice += float64(item.Quantity) * item.UnitPrice
			}
			orderView.TotalPrice = totalPrice

			ordersView = append(ordersView, orderView)
		}

		tmpl, err := template.ParseFiles(
			"templates/header.tmpl",
			"templates/footer.tmpl",
			"templates/user_navigation_orders.tmpl",
			"templates/user_orders.tmpl",
		)
		if err != nil {
			http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tmpl.ExecuteTemplate(w, "user_navigation_orders", ordersView); err != nil {
			http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		}
	})

	// Добавим маршрут для удаления заказа
	router.HandleFunc("/orders/delete/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		orderID := vars["id"]

		// Удаление всех связанных OrderItems
		if err := db.Where("order_id = ?", orderID).Delete(&OrderItem{}).Error; err != nil {
			http.Error(w, "Could not delete order items", http.StatusInternalServerError)
			return
		}

		// Удаление самого заказа
		if err := db.Delete(&Order{}, orderID).Error; err != nil {
			http.Error(w, "Could not delete order", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/user/navigation/orders", http.StatusSeeOther)
	})

	// router.HandleFunc("/user/navigation/orders", func(w http.ResponseWriter, r *http.Request) {
	// 	userID, err := getSessionUserID(r)
	// 	if err != nil {
	// 		log.Println("Redirecting to login: ", err)
	// 		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	// 		return
	// 	}

	// 	var user User
	// 	if err := db.First(&user, userID).Error; err != nil {
	// 		http.Error(w, "User not found: "+err.Error(), http.StatusNotFound)
	// 		return
	// 	}

	// 	var orders []Order
	// 	if err := db.Preload("OrderItems.Product").Where("user_id = ?", userID).Find(&orders).Error; err != nil {
	// 		log.Printf("Failed to fetch orders: %v\n", err)
	// 		http.Error(w, "Failed to fetch orders", http.StatusInternalServerError)
	// 		return
	// 	}

	// 	var ordersWithTotal []struct {
	// 		Order
	// 		Total float64
	// 	}

	// 	for _, order := range orders {
	// 		var total float64
	// 		for _, item := range order.OrderItems {
	// 			total += float64(item.Quantity) * item.UnitPrice
	// 		}
	// 		ordersWithTotal = append(ordersWithTotal, struct {
	// 			Order
	// 			Total float64
	// 		}{
	// 			Order: order,
	// 			Total: total,
	// 		})
	// 	}

	// 	tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/footer.tmpl", "templates/user_orders.tmpl", "templates/user_navigation_orders.tmpl")
	// 	if err != nil {
	// 		log.Printf("Error loading templates: %v\n", err)
	// 		http.Error(w, "Failed to load templates", http.StatusInternalServerError)
	// 		return
	// 	}

	// 	productMap := make(map[uint]Product)
	// 	for _, order := range orders {
	// 		for _, item := range order.OrderItems {
	// 			productMap[item.ProductID] = item.Product
	// 		}
	// 	}

	// 	data := struct {
	// 		User   User
	// 		Orders []struct {
	// 			Order
	// 			Total float64
	// 		}
	// 		ProductMap map[uint]Product
	// 	}{
	// 		User:       user,
	// 		Orders:     ordersWithTotal,
	// 		ProductMap: productMap,
	// 	}

	// 	if err := tmpl.ExecuteTemplate(w, "user_navigation_orders", data); err != nil {
	// 		log.Printf("Error executing template: %v\n", err)
	// 		http.Error(w, "Failed to execute template", http.StatusInternalServerError)
	// 	}
	// })

	router.HandleFunc("/checkout", func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID пользователя из сессии
		userID, err := getSessionUserID(r)
		if err != nil {
			log.Println("Ошибка при получении ID пользователя:", err)
			http.Redirect(w, r, "/login/", http.StatusSeeOther) // Перенаправление на страницу входа, если пользователь не аутентифицирован
			return
		}

		db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
		if err != nil {
			fmt.Printf("Error opening database: %v\n", err)
			return
		}

		// Пытаемся создать заказ из корзины пользователя
		if err := services.CreateOrder(db, userID); err != nil {
			log.Printf("Ошибка при создании заказа: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Перенаправление на страницу подтверждения заказа или на главную страницу с сообщением об успешном создании заказа
		http.Redirect(w, r, "/order/success", http.StatusSeeOther)
	})

	router.HandleFunc("/order/success", func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID пользователя из сессии
		userID, err := getSessionUserID(r)
		if err != nil {
			log.Printf("Error getting user ID: %v\n", err)
			http.Redirect(w, r, "/login/", http.StatusSeeOther) // Перенаправление на страницу входа при ошибке
			return
		}

		// Находим пользователя в базе данных
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			log.Printf("User not found: %v\n", err)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Загрузка шаблона
		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/order_success.tmpl", "templates/footer.tmpl")
		if err != nil {
			log.Printf("Error parsing template: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Подготовка данных для шаблона
		data := struct {
			Name string // Имя пользователя для отображения на странице
		}{
			Name: user.Name, // Использование имени извлеченного пользователя
		}

		// Выполнение шаблона
		if err := tmpl.ExecuteTemplate(w, "order_success", data); err != nil {
			log.Printf("Error executing template: %v\n", err)
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	router.HandleFunc("/user/dashboard", func(w http.ResponseWriter, r *http.Request) {
		userID, err := getSessionUserID(r)
		if err != nil {
			log.Println("Redirecting to login due to error:", err)
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}

		var user models.User
		if err := db.First(&user, userID).Error; err != nil {
			http.Error(w, "User not found: "+err.Error(), http.StatusNotFound)
			return
		}

		// Загрузка шаблонов напрямую без использования prepareTemplate
		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/user_navigation.tmpl", "templates/footer.tmpl")
		if err != nil {
			log.Printf("Error parsing template files: %v\n", err)
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		// Создание данных для шаблона
		data := struct {
			Name string
		}{
			Name: user.Name,
		}

		// Выполнение шаблона
		if err := tmpl.ExecuteTemplate(w, "user_navigation", data); err != nil {
			log.Printf("Error executing template: %v\n", err)
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	// Добавление в корзину
	router.HandleFunc("/cart/add/", func(w http.ResponseWriter, r *http.Request) {
		userID, err := getSessionUserID(r)
		fmt.Println(userID)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		productID, _ := strconv.Atoi(r.FormValue("product_id"))
		quantity, _ := strconv.Atoi(r.FormValue("quantity"))
		redirectURL := r.FormValue("redirect_url")

		var cartItem CartItem
		db.FirstOrCreate(&cartItem, CartItem{ProductID: uint(productID), UserID: uint(userID)})
		cartItem.Quantity += quantity
		db.Save(&cartItem)

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// Просмотр корзины
	router.HandleFunc("/cart/view/", func(w http.ResponseWriter, r *http.Request) {
		userID, err := getSessionUserID(r)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		var cartItems []CartItem
		db.Preload("Product").Where("user_id = ?", userID).Find(&cartItems)

		for _, item := range cartItems {
			fmt.Fprintf(w, "Product: %s, Quantity: %d\n", item.Product.Name, item.Quantity)
		}
	})

	// Удаление из корзины
	router.HandleFunc("/cart/remove", func(w http.ResponseWriter, r *http.Request) {
		userID, err := getSessionUserID(r)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		productID, _ := strconv.Atoi(r.FormValue("product_id"))
		db.Where("user_id = ? AND product_id = ?", userID, productID).Delete(&CartItem{})
		fmt.Fprintf(w, "Product %d removed from cart for user %d", productID, userID)
	})

	adminPanelHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles(
			"templates/header.tmpl",
			"templates/admin_panel.tmpl",
			"templates/footer.tmpl",
		)
		if err != nil {
			http.Error(w, "Ошибка разбора шаблона", http.StatusInternalServerError)
			return
		}

		if err := tmpl.ExecuteTemplate(w, "admin_panel", nil); err != nil {
			http.Error(w, "Ошибка выполнения шаблона", http.StatusInternalServerError)
		}
	})

	// Настройка маршрутизации с применением middleware для аутентификации администратора
	router.Handle("/admin", AdminAuthMiddleware(adminPanelHandler)).Methods("GET")

	adminProducts := http.HandlerFunc(adminProductsHandler)
	router.Handle("/admin/products", AdminAuthMiddleware(adminProducts)).Methods("GET")

	addProductHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			var categories []Category
			if err := db.Find(&categories).Error; err != nil {
				http.Error(w, "Failed to fetch categories", http.StatusInternalServerError)
				return
			}
			data := AdminPanelData{
				Categories: categories,
			}
			tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/add_product.tmpl", "templates/footer.tmpl")
			if err != nil {
				http.Error(w, "Error parsing template", http.StatusInternalServerError)
				return
			}
			if err := tmpl.ExecuteTemplate(w, "add_product", data); err != nil {
				http.Error(w, "Error executing template", http.StatusInternalServerError)
			}
		} else if r.Method == "POST" {
			err := r.ParseMultipartForm(10 << 20) // Максимальный размер файла 10MB
			if err != nil {
				http.Error(w, "File too large.", http.StatusBadRequest)
				return
			}

			file, header, err := r.FormFile("image")
			if err != nil {
				http.Error(w, "Invalid file", http.StatusBadRequest)
				return
			}
			defer file.Close()

			// Создаем файл в нужном директории
			filePath := "static/images/" + header.Filename
			out, err := os.Create(filePath)
			if err != nil {
				http.Error(w, "Unable to create the file for writing. Check your write access privilege", http.StatusInternalServerError)
				return
			}
			defer out.Close()

			// Копируем файл
			_, err = io.Copy(out, file)
			if err != nil {
				http.Error(w, "Error occurred copying the file", http.StatusInternalServerError)
				return
			}

			name := r.FormValue("name")
			description := r.FormValue("description")
			price, _ := strconv.ParseFloat(r.FormValue("price"), 64)
			categoryID, _ := strconv.Atoi(r.FormValue("category_id"))
			product := Product{
				Name:        name,
				Description: description,
				Price:       price,
				CategoryID:  uint(categoryID),
				Image:       filePath, // Сохраняем путь к файлу
			}
			if err := db.Create(&product).Error; err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/products", http.StatusSeeOther)
		}
	})
	router.Handle("/admin/products/add", AdminAuthMiddleware(addProductHandler)).Methods("GET", "POST")

	editProductHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])
		var product Product
		if err := db.First(&product, id).Error; err != nil {
			http.Error(w, "Product not found", http.StatusNotFound)
			return
		}
		var categories []Category
		if err := db.Find(&categories).Error; err != nil {
			http.Error(w, "Failed to fetch categories", http.StatusInternalServerError)
			return
		}
		data := struct {
			Product    Product
			Categories []Category
		}{
			Product:    product,
			Categories: categories,
		}
		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/edit_product.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		if err := tmpl.ExecuteTemplate(w, "edit_product", data); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})
	router.Handle("/admin/products/{id:[0-9]+}/edit", AdminAuthMiddleware(editProductHandler)).Methods("GET")

	updateProductHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])               // Используем mux.Vars для получения ID из URL
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB
			http.Error(w, "File upload error", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// Создаем путь к файлу внутри директории сервера
		filePath := fmt.Sprintf("static/images/%s", header.Filename)
		out, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to create the file", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, file)
		if err != nil {
			http.Error(w, "Failed to save the file", http.StatusInternalServerError)
			return
		}

		name := r.FormValue("name")
		description := r.FormValue("description")
		price, _ := strconv.ParseFloat(r.FormValue("price"), 64)
		categoryID, _ := strconv.Atoi(r.FormValue("category_id"))

		var product Product
		if db.First(&product, id).Error != nil {
			http.Error(w, "Product not found", http.StatusNotFound)
			return
		}

		product.Name = name
		product.Description = description
		product.Price = price
		product.CategoryID = uint(categoryID)
		product.Image = filePath // Убедитесь, что путь начинается без дополнительного слэша

		if err := db.Save(&product).Error; err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/products", http.StatusSeeOther)
	})

	// Применение AdminAuthMiddleware к маршруту обновления продукта
	router.Handle("/admin/products/{id:[0-9]+}/update", AdminAuthMiddleware(updateProductHandler)).Methods("POST")

	deleteProductHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])
		var product Product
		if db.First(&product, id).Error != nil {
			http.Error(w, "Product not found", http.StatusNotFound)
			return
		}
		if err := db.Delete(&product).Error; err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/products", http.StatusSeeOther)
	})
	router.Handle("/admin/products/{id:[0-9]+}/delete", AdminAuthMiddleware(deleteProductHandler)).Methods("POST")

	adminUsersHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var users []User
		if err := db.Find(&users).Error; err != nil {
			http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
			return
		}
		data := AdminPanelData{
			Users: users,
		}
		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/admin_users.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		if err := tmpl.ExecuteTemplate(w, "admin_users", data); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	editUserHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])
		var user User
		if err := db.First(&user, id).Error; err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/edit_users.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		data := struct {
			User User
		}{
			User: user,
		}

		if err := tmpl.ExecuteTemplate(w, "edit_user", data); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	updateUserHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		name := r.FormValue("name")
		surname := r.FormValue("surname")
		email := r.FormValue("email")
		password := r.FormValue("password")
		isAdminStr := r.FormValue("isAdmin")
		isAdmin := false

		if isAdminStr == "true" {
			isAdmin = true
		}

		if name == "" || surname == "" || email == "" || password == "" {
			http.Error(w, "All fields must be filled", http.StatusBadRequest)
			return
		}

		var user User
		if err := db.First(&user, id).Error; err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		user.Name = name
		user.Surname = surname
		user.Email = email
		user.Password = password
		user.IsAdmin = isAdmin

		if err := db.Save(&user).Error; err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	})

	deleteUserHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(mux.Vars(r)["id"])
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		var user User
		if db.First(&user, id).Error != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if err := db.Delete(&user).Error; err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	})

	// Применение AdminAuthMiddleware к маршрутам
	router.Handle("/admin/users", AdminAuthMiddleware(adminUsersHandler)).Methods("GET")
	router.Handle("/admin/users/{id:[0-9]+}/edit", AdminAuthMiddleware(editUserHandler)).Methods("GET")
	router.Handle("/admin/users/{id:[0-9]+}/update", AdminAuthMiddleware(updateUserHandler)).Methods("POST")
	router.Handle("/admin/users/{id:[0-9]+}/delete", AdminAuthMiddleware(deleteUserHandler)).Methods("POST")

	addArticleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			title := r.FormValue("title")
			content := r.FormValue("content")
			author := r.FormValue("author")
			publishedAtStr := r.FormValue("published_at")
			log.Println("Полученная дата и время:", publishedAtStr) // Логирование для отладки

			// Парсинг даты без временной зоны
			publishedAt, err := time.Parse("2006-01-02T15:04", publishedAtStr)
			if err != nil {
				log.Printf("Ошибка парсинга даты: %v", err)
				http.Error(w, "Неверный формат даты. Используйте формат ГГГГ-ММ-ДДЧЧ:ММ.", http.StatusBadRequest)
				return
			}

			article := Article{
				Title:       title,
				Content:     content,
				Author:      author,
				PublishedAt: publishedAt,
			}
			if err := db.Create(&article).Error; err != nil {
				http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/articles", http.StatusSeeOther)
		} else {
			tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/add_article.tmpl", "templates/footer.tmpl")
			if err != nil {
				http.Error(w, "Ошибка разбора шаблона", http.StatusInternalServerError)
				return
			}
			if err := tmpl.ExecuteTemplate(w, "add_article", nil); err != nil {
				http.Error(w, "Ошибка выполнения шаблона", http.StatusInternalServerError)
			}
		}
	})

	adminArticlesHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var articles []Article
		if err := db.Find(&articles).Error; err != nil {
			http.Error(w, "Failed to fetch articles", http.StatusInternalServerError)
			return
		}
		data := struct {
			Articles []Article
		}{
			Articles: articles,
		}

		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/admin_articles.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		if err := tmpl.ExecuteTemplate(w, "admin_articles", data); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	editArticleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(mux.Vars(r)["id"])
		if err != nil {
			http.Error(w, "Invalid article ID", http.StatusBadRequest)
			return
		}

		var article Article
		if err := db.First(&article, id).Error; err != nil {
			http.Error(w, "Article not found", http.StatusNotFound)
			return
		}

		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/edit_article.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		// Обратите внимание, что теперь мы передаем структуру с полем Article напрямую
		if err := tmpl.ExecuteTemplate(w, "edit_article", struct{ Article Article }{Article: article}); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	updateArticleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			http.Error(w, "Invalid article ID", http.StatusBadRequest)
			return
		}

		var article Article
		if err := db.First(&article, id).Error; err != nil {
			http.Error(w, "Article not found", http.StatusNotFound)
			return
		}

		title := r.FormValue("title")
		content := r.FormValue("content")
		author := r.FormValue("author")
		publishedAtStr := r.FormValue("published_at")

		// Assume the browser sends the date in "YYYY-MM-DDThh:mm" format
		publishedAt, err := time.Parse("2006-01-02T15:04", publishedAtStr)
		if err != nil {
			log.Printf("Date parsing error: %v", err)
			http.Error(w, "Invalid date format. Please use YYYY-MM-DDThh:mm format.", http.StatusBadRequest)
			return
		}

		article.Title = title
		article.Content = content
		article.Author = author
		article.PublishedAt = publishedAt

		if err := db.Save(&article).Error; err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/articles", http.StatusSeeOther)
	})

	deleteArticleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])
		var article Article
		if db.First(&article, id).Error != nil {
			http.Error(w, "Article not found", http.StatusNotFound)
			return
		}
		if err := db.Delete(&article).Error; err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/articles", http.StatusSeeOther)
	})

	// Маршрутизация с использованием AdminAuthMiddleware
	router.Handle("/admin/articles/add", AdminAuthMiddleware(addArticleHandler)).Methods("GET", "POST")
	router.Handle("/admin/articles/{id:[0-9]+}/edit", AdminAuthMiddleware(editArticleHandler)).Methods("GET")
	router.Handle("/admin/articles/{id:[0-9]+}/update", AdminAuthMiddleware(updateArticleHandler)).Methods("POST")
	router.Handle("/admin/articles/{id:[0-9]+}/delete", AdminAuthMiddleware(deleteArticleHandler)).Methods("POST")
	router.Handle("/admin/articles", AdminAuthMiddleware(adminArticlesHandler)).Methods("GET")

	router.HandleFunc("/articles", func(w http.ResponseWriter, r *http.Request) {
		var articles []Article
		if err := db.Find(&articles).Error; err != nil {
			http.Error(w, "Failed to fetch articles", http.StatusInternalServerError)
			return
		}

		articlesTmpl := template.New("articles_list").Funcs(template.FuncMap{
			"truncate": truncate, // Добавление функции обрезки текста
		})

		// Парсинг файлов шаблона
		articlesTmpl, err := articlesTmpl.ParseFiles("templates/header.tmpl", "templates/articles_list.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing articles list template: %v", err), http.StatusInternalServerError)
			return
		}

		// Подготовка данных для шаблона
		articlesData := struct {
			Articles   []Article // Подготовка списка статей для отображения
			CurrentURL string
		}{
			Articles:   articles,
			CurrentURL: r.URL.RequestURI(),
		}

		// Рендеринг шаблона с данными
		if err := articlesTmpl.ExecuteTemplate(w, "articles_list", articlesData); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	router.HandleFunc("/articles/{id:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		idStr := mux.Vars(r)["id"]
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid article ID", http.StatusBadRequest)
			return
		}

		var article Article
		if err := db.First(&article, id).Error; err != nil {
			http.Error(w, "Article not found", http.StatusNotFound)
			return
		}

		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/article_detail.tmpl", "templates/footer.tmpl")
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		if err := tmpl.ExecuteTemplate(w, "article_detail", article); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
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

		http.Redirect(w, r, "/login/", http.StatusFound)

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

	adminOrdersHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var orders []Order
		if err := db.Preload("OrderItems").Find(&orders).Error; err != nil {
			log.Printf("Error fetching orders: %v", err)
			http.Error(w, "Failed to fetch orders", http.StatusInternalServerError)
			return
		}

		// Load user and product information for each order
		orderDetails := make([]struct {
			Order      Order
			UserName   string
			UserEmail  string
			OrderItems []struct {
				ProductName string
				Quantity    int
				UnitPrice   float64
			}
		}, len(orders))

		for i, order := range orders {
			// Get user information
			var user User
			if err := db.First(&user, order.UserID).Error; err != nil {
				log.Printf("Error loading user for order: %v", err)
				continue
			}

			orderDetails[i].Order = order
			orderDetails[i].UserName = user.Name + " " + user.Surname
			orderDetails[i].UserEmail = user.Email

			// Get product information for each order item
			orderDetails[i].OrderItems = make([]struct {
				ProductName string
				Quantity    int
				UnitPrice   float64
			}, len(order.OrderItems))

			for j, item := range order.OrderItems {
				var product Product
				if err := db.First(&product, item.ProductID).Error; err != nil {
					log.Printf("Error loading product for order item: %v", err)
					continue
				}

				orderDetails[i].OrderItems[j] = struct {
					ProductName string
					Quantity    int
					UnitPrice   float64
				}{
					ProductName: product.Name,
					Quantity:    item.Quantity,
					UnitPrice:   item.UnitPrice,
				}
			}
		}

		data := struct {
			Orders []struct {
				Order      Order
				UserName   string
				UserEmail  string
				OrderItems []struct {
					ProductName string
					Quantity    int
					UnitPrice   float64
				}
			}
		}{
			Orders: orderDetails,
		}

		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/admin_orders.tmpl", "templates/footer.tmpl")
		if err != nil {
			log.Printf("Error parsing template: %v", err)
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		if err := tmpl.ExecuteTemplate(w, "admin_orders", data); err != nil {
			log.Printf("Error executing template: %v", err)
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	editOrderHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])
		var order Order
		if err := db.Preload("OrderItems").First(&order, id).Error; err != nil {
			log.Printf("Error fetching order: %v", err)
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}

		// Get user information
		var user User
		if err := db.First(&user, order.UserID).Error; err != nil {
			log.Printf("Error loading user for order: %v", err)
			http.Error(w, "Error loading user", http.StatusInternalServerError)
			return
		}

		// Get product information for each order item
		orderItems := make([]struct {
			ProductName string
			Quantity    int
			UnitPrice   float64
		}, len(order.OrderItems))

		for j, item := range order.OrderItems {
			var product Product
			if err := db.First(&product, item.ProductID).Error; err != nil {
				log.Printf("Error loading product for order item: %v", err)
				continue
			}

			orderItems[j] = struct {
				ProductName string
				Quantity    int
				UnitPrice   float64
			}{
				ProductName: product.Name,
				Quantity:    item.Quantity,
				UnitPrice:   item.UnitPrice,
			}
		}

		tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/edit_order.tmpl", "templates/footer.tmpl")
		if err != nil {
			log.Printf("Error parsing template: %v", err)
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		data := struct {
			Order      Order
			UserName   string
			UserEmail  string
			OrderItems []struct {
				ProductName string
				Quantity    int
				UnitPrice   float64
			}
		}{
			Order:      order,
			UserName:   user.Name + " " + user.Surname,
			UserEmail:  user.Email,
			OrderItems: orderItems,
		}

		if err := tmpl.ExecuteTemplate(w, "edit_order", data); err != nil {
			log.Printf("Error executing template: %v", err)
			http.Error(w, "Error executing template", http.StatusInternalServerError)
		}
	})

	// Handler for updating a specific order
	updateOrderHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			log.Printf("Invalid order ID: %v", err)
			http.Error(w, "Invalid order ID", http.StatusBadRequest)
			return
		}

		status := r.FormValue("status")

		var order Order
		if err := db.First(&order, id).Error; err != nil {
			log.Printf("Error fetching order: %v", err)
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}

		order.Status = status

		if err := db.Save(&order).Error; err != nil {
			log.Printf("Error saving order: %v", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/orders", http.StatusSeeOther)
	})

	// Handler for deleting a specific order
	deleteOrderHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(mux.Vars(r)["id"])
		if err != nil {
			log.Printf("Invalid order ID: %v", err)
			http.Error(w, "Invalid order ID", http.StatusBadRequest)
			return
		}

		var order Order
		if db.First(&order, id).Error != nil {
			log.Printf("Error fetching order: %v", err)
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}
		if err := db.Delete(&order).Error; err != nil {
			log.Printf("Error deleting order: %v", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/orders", http.StatusSeeOther)
	})

	// Apply AdminAuthMiddleware to routes
	router.Handle("/admin/orders", AdminAuthMiddleware(adminOrdersHandler)).Methods("GET")
	router.Handle("/admin/orders/{id:[0-9]+}/edit", AdminAuthMiddleware(editOrderHandler)).Methods("GET")
	router.Handle("/admin/orders/{id:[0-9]+}/update", AdminAuthMiddleware(updateOrderHandler)).Methods("POST")
	router.Handle("/admin/orders/{id:[0-9]+}/delete", AdminAuthMiddleware(deleteOrderHandler)).Methods("POST")

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Находим все продукты в базе данных
		var products []Product
		if result := db.Find(&products); result.Error != nil {
			http.Error(w, "Failed to fetch products", http.StatusInternalServerError)
			return
		}

		// Загружаем и объединяем шаблоны
		tmpl := template.Must(template.ParseFiles("templates/header.tmpl", "templates/footer.tmpl", "templates/index_user.tmpl"))

		// Создаем данные для шаблона
		data := struct {
			Name       string
			Products   []Product
			CurrentURL string
		}{
			Products:   products,
			CurrentURL: r.URL.RequestURI(),
		}

		// Выполняем шаблон с данными
		if err := tmpl.ExecuteTemplate(w, "index_user", data); err != nil {
			http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
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

	router.HandleFunc("/catalog/products/{categoryID}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		categoryID, err := strconv.Atoi(vars["categoryID"])
		if err != nil {
			http.Error(w, "Invalid category ID: "+vars["categoryID"], http.StatusBadRequest)
			return
		}

		log.Printf("Processing category ID: %d", categoryID)

		var products []Product
		if categoryID == 0 {
			// Если CategoryID равен 0, выводим все продукты
			if err := db.Find(&products).Error; err != nil {
				http.Error(w, "Failed to fetch products: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// Если CategoryID не равен 0, выводим продукты по категории
			if err := db.Where("category_id = ?", categoryID).Find(&products).Error; err != nil {
				http.Error(w, "Failed to fetch products: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if len(products) == 0 {
			http.Error(w, "No products found for category ID "+vars["categoryID"], http.StatusNotFound)
			return
		}

		tmpl := template.Must(template.ParseFiles("templates/header.tmpl", "templates/footer.tmpl", "templates/catalog.tmpl"))

		data := struct {
			ID         int
			Name       string
			Products   []Product
			CurrentURL string
			CategoryID int
		}{
			ID:         0, // Замените 0 на соответствующее значение, если необходимо
			Products:   products,
			CurrentURL: r.URL.RequestURI(),
			CategoryID: categoryID,
		}

		if err := tmpl.ExecuteTemplate(w, "catalog", data); err != nil {
			http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		}
	})

	err = http.ListenAndServe(":8060", router)
	if err != nil {
		log.Fatal(err)
	}
}

func getSessionUserID(r *http.Request) (uint, error) {
	// Извлекаем токен из куки
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// Токен не найден в куки
			log.Println("No token provided")
			return 0, fmt.Errorf("Unauthorized - No token provided")
		}
		// Ошибка при получении куки
		log.Printf("Error retrieving cookie: %v", err)
		return 0, fmt.Errorf("Unauthorized - Bad request")
	}

	// Парсинг токена
	tokenClaims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, tokenClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return 0, fmt.Errorf("Unauthorized - Error parsing token")
	}

	if !token.Valid {
		log.Println("Invalid token")
		return 0, fmt.Errorf("Unauthorized - Invalid token")
	}

	// Преобразуем userID к типу uint
	userID, ok := tokenClaims["userID"].(string)
	if !ok {
		log.Println("userID claim missing in token")
		return 0, fmt.Errorf("Unauthorized - userID claim missing")
	}

	userIDUint, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		log.Printf("Error converting userID to uint: %v", err)
		return 0, fmt.Errorf("Error converting userID")
	}

	return uint(userIDUint), nil
}

// Функция для извлечения JWT из заголовка Authorization
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}
	return ""
}

func adminProductsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}

	log.Println("Entered adminProductsHandler")
	var products []Product
	var categories []Category
	if err := db.Find(&products).Error; err != nil {
		http.Error(w, "Failed to fetch products", http.StatusInternalServerError)
		return
	}
	if err := db.Find(&categories).Error; err != nil {
		http.Error(w, "Failed to fetch categories", http.StatusInternalServerError)
		return
	}

	data := AdminPanelData{
		Products:   products,
		Categories: categories,
	}

	tmpl, err := template.ParseFiles("templates/header.tmpl", "templates/footer.tmpl", "templates/admin_products.tmpl")
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "admin_products", data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}

func AdminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Извлечение токена из куки
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Unauthorized - No token provided", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Unauthorized - Bad request", http.StatusBadRequest)
			return
		}

		// Парсинг токена
		tokenClaims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(cookie.Value, tokenClaims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil {
			http.Error(w, "Unauthorized - Error parsing token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}

		userId, ok := tokenClaims["userID"].(string)
		if !ok {
			http.Error(w, "Пользователя не существует", http.StatusUnauthorized)
			return
		}

		db, err := gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
		if err != nil {
			fmt.Printf("Error opening database: %v\n", err)
			return
		}

		var user User
		if err := db.
			Where("id = ?", userId).
			Find(&user).
			Error; err != nil {

			http.Error(w, "Пользователя не существует", http.StatusUnauthorized)
			return
		}

		// Проверка, является ли пользователь администратором
		if ok && user.IsAdmin {
			log.Printf("Admin access granted for user ID: %v", tokenClaims["userID"]) // Логирование доступа админа
			next.ServeHTTP(w, r)                                                      // Передача управления следующему обработчику, если пользователь админ
		} else {
			http.Error(w, "Unauthorized - You are not an administrator", http.StatusUnauthorized)
		}
	})
}
