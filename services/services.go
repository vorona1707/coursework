package services

import (
	"log"
	"organic_store/models" // Убедитесь, что путь импорта соответствует вашей структуре проекта

	"gorm.io/gorm"
)

// CreateOrder создает заказ из корзины пользователя
func CreateOrder(db *gorm.DB, userID uint) error {
	var cartItems []models.CartItem
	if err := db.Preload("Product").Where("user_id = ?", userID).Find(&cartItems).Error; err != nil {
		log.Printf("Ошибка при получении товаров из корзины: %v", err)
		return err
	}

	// Подсчет общей стоимости заказа
	var totalPrice float64
	for _, item := range cartItems {
		totalPrice += item.Product.Price * float64(item.Quantity)
	}

	// Создание заказа
	order := models.Order{
		UserID:     userID,
		TotalPrice: totalPrice, // Установка общей стоимости
		Status:     "Создан",   // Установка статуса при создании заказа
	}

	// Сохранение заказа в базе данных
	if err := db.Create(&order).Error; err != nil {
		log.Printf("Ошибка при создании заказа: %v", err)
		return err
	}

	// Создание элементов заказа
	for _, item := range cartItems {
		orderItem := models.OrderItem{
			OrderID:   order.ID,
			ProductID: item.ProductID,
			Quantity:  item.Quantity,
			UnitPrice: item.Product.Price,
		}
		if err := db.Create(&orderItem).Error; err != nil {
			log.Printf("Ошибка при создании элемента заказа: %v", err)
			return err
		}
	}

	// Очистка корзины после создания заказа
	if err := db.Where("user_id = ?", userID).Delete(&models.CartItem{}).Error; err != nil {
		log.Printf("Ошибка при очистке корзины: %v", err)
		return err
	}

	return nil
}
