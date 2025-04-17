package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Order struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID        string             `bson:"userID" json:"userID"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Price         float64            `json:"price"`
	ImageURL      string             `json:"imageURL"`
	Status        string             `json:"status"`
	PaymentMethod string             `json:"paymentMethod,omitempty"`
}
