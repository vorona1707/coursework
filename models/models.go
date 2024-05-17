package models

import (
	"time"

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

type Category struct {
	gorm.Model
	ID       uint `gorm:"primaryKey"`
	Name     string
	Products []Product
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

type contextKey string
