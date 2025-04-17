package models

type CartItem struct {
	ProductID string `bson:"product_id"`
	UserID    string `bson:"user_id"`

	Name        string `json:"name"`
	Description string `json:"description"`
	Price       int    `json:"price"`
	ImageURL    string `json:"imageurl"`
}
