package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"go_project/models"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mu                   sync.Mutex
	client               *mongo.Client
	usersCollection      *mongo.Collection
	ordersCollection     *mongo.Collection
	cartCollection       *mongo.Collection
	productsCollection   *mongo.Collection
	cartItems            []models.Product
	products             = []Product{}
	ctx                  context.Context
	complaintsCollection *mongo.Collection
	contactCollection    *mongo.Collection
)

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	Username string             `bson:"username" json:"username"`
	Password string             `bson:"password" json:"password"`
	Role     string             `bson:"role" json:"role"`
}
type Product struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	Price       float64 `json:"price"`
	Description string  `json:"description"`
}
type CartItem struct {
	ProductID string `bson:"product_id"`
	UserID    string `bson:"user_id"`

	Name        string `json:"name"`
	Description string `json:"description"`
	Price       int    `json:"price"`
	ImageURL    string `json:"imageurl"`
}
type Contact struct {
	Phone    string `bson:"phone" json:"phone"`
	Whatsapp string `bson:"whatsapp" json:"whatsapp"`
	Email    string `bson:"email" json:"email"`
}
type Order struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID         string             `bson:"user_id" json:"user_id"`
	Name           string             `bson:"name" json:"name"`
	Description    string             `bson:"description" json:"description"`
	Price          float64            `bson:"price" json:"price"`
	ImageURL       string             `bson:"imageurl" json:"imageURL"`
	Status         string             `bson:"status" json:"status"`
	OrderID        string             `bson:"order_id" json:"order_id"`
	CustomerID     string             `bson:"customer_id" json:"customer_id"`
	OrderDate      time.Time          `bson:"order_date" json:"order_date"`
	ExpectedDel    time.Time          `bson:"expected_delivery" json:"expected_delivery"`
	Address        string             `bson:"address,omitempty" json:"address,omitempty"`
	Rating         int                `bson:"rating,omitempty" json:"rating,omitempty"`
	DeliveryStatus string             `bson:"delivery_status,omitempty" json:"delivery_status,omitempty"` // e.g., "Pending", "Delivered"
}
type DashboardData struct {
	TotalUsers    int64 `json:"totalUsers"`
	TotalProducts int64 `json:"totalProducts"`
	OrdersToday   int64 `json:"ordersToday"`
}
type Complaint struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	CustomerID  string             `bson:"customer_id" json:"customer_id"`
	Description string             `bson:"description" json:"description"`
	Status      string             `bson:"status" json:"status"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

type ChatMessage struct {
	Type     string `json:"type"` // "user" or "bot"
	Content  string `json:"content"`
	Time     string `json:"time"`
	Metadata string `json:"metadata,omitempty"` // For links, buttons, etc.
}

func main() {
	initDB()
	go startTCPServer()
	startWebServer()
}

func initDB() {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://vgugan16:gugan2004@cluster0.qyh1fuo.mongodb.net/golang?retryWrites=true&w=majority&appName=Cluster0"))
	if err != nil {
		log.Fatal("❌ Failed to connect to MongoDB:", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("❌ MongoDB connection error:", err)
	}

	fmt.Println("✅ Connected to MongoDB!")

	db := client.Database("authdb")
	usersCollection = db.Collection("users")
	productsCollection = db.Collection("products")
	ordersCollection = db.Collection("orders")
	cartCollection = db.Collection("cart")
	complaintsCollection = db.Collection("complaints")
	contactCollection = db.Collection("contact")
}

func startTCPServer() {
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatal("❌ Error starting TCP server:", err)
	}
	defer listener.Close()
	fmt.Println("🔐 TCP Authentication Server is listening on port 8081...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("⚠️ Connection error:", err)
			continue
		}
		go handleTCPAuth(conn)
	}
}
func handleTCPAuth(conn net.Conn) {
	defer conn.Close()

	// Reading the credentials sent by the client
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == io.EOF {
		return
	}
	if err != nil {
		fmt.Println("⚠️ Read error:", err)
		return
	}

	// Parse the credentials (username:password)
	credentials := strings.TrimSpace(string(buffer[:n]))
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		conn.Write([]byte("FAIL\n"))
		return
	}
	username := strings.TrimSpace(parts[0])
	password := strings.TrimSpace(parts[1])

	// Fetching the user from the database
	var user User
	err = usersCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err == nil && user.Password == password {
		// Sending back the role and user ID (in the case of success)
		conn.Write([]byte("SUCCESS:" + user.Role + ":" + user.ID.Hex() + "\n"))
	} else {
		// Send failure message if user not found or password mismatch
		conn.Write([]byte("FAIL\n"))
	}
}

func startWebServer() {
	r := mux.NewRouter()

	// Static page routes
	r.HandleFunc("/", loginPage).Methods("GET")
	r.HandleFunc("/signup", signupPage).Methods("GET")
	r.HandleFunc("/dashboard.html", serveStaticPage("static/dashboard.html")).Methods("GET")
	r.HandleFunc("/admin.html", serveStaticPage("static/admin.html")).Methods("GET")
	r.HandleFunc("/viewproduct.html", serveStaticPage("static/viewproduct.html")).Methods("GET")
	r.HandleFunc("/view_cart.html", serveStaticPage("static/view_cart.html")).Methods("GET")
	r.HandleFunc("/my_orders.html", serveStaticPage("static/my_orders.html")).Methods("GET")
	r.HandleFunc("/payment_gateway.html", serveStaticPage("static/payment_gateway.html")).Methods("GET")
	r.HandleFunc("/ai_classifier.html", serveStaticPage("static/ai_classifier.html")).Methods("GET")
	r.HandleFunc("/profile.html", serveStaticPage("static/profile.html")).Methods("GET")
	r.HandleFunc("/manage_users.html", serveStaticPage("static/manage_users.html")).Methods("GET")
	r.HandleFunc("/manage_product.html", serveStaticPage("static/manage_product.html")).Methods("GET")
	r.HandleFunc("/edit_product.html", serveStaticPage("static/edit_product.html")).Methods("GET")
	r.HandleFunc("/track.html", serveStaticPage("static/track.html")).Methods("GET")
	r.HandleFunc("/orders.html", serveStaticPage("static/orders.html")).Methods("GET")
	r.HandleFunc("/chatbot.html", serveStaticPage("static/chatbot.html")).Methods("GET")
	r.HandleFunc("/contact.html", serveStaticPage("static/contact.html")).Methods("GET")
	r.HandleFunc("/image.html", serveStaticPage("static/image.html")).Methods("GET")
	r.HandleFunc("/complaint.html", serveStaticPage("static/complaint.html")).Methods("GET")

	// Auth
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/signup", signupHandler).Methods("POST")

	// REST API
	r.HandleFunc("/api/products", GetAllProducts).Methods("GET")
	r.HandleFunc("/api/products", AddProductHandler).Methods("POST")
	r.HandleFunc("/api/cart/add", AddToCartHandler).Methods("POST")
	r.HandleFunc("/api/cart", ViewCartHandler).Methods("GET")
	r.HandleFunc("/api/orders/place", PlaceOrderHandler).Methods("POST")
	r.HandleFunc("/api/orders", GetOrdersHandler).Methods("GET")
	r.HandleFunc("/api/order/latest", GetLatestOrderHandler).Methods("GET")
	r.HandleFunc("/api/placeOrder", PlaceOrderHandler).Methods("POST")
	r.HandleFunc("/api/user/profile", GetUserProfileHandler).Methods("GET")

	r.HandleFunc("/api/classify", ClassifyImageHandler).Methods("POST")
	r.HandleFunc("/api/users", getUsers).Methods("GET")
	r.HandleFunc("/api/users/{username}", deleteUser).Methods("DELETE")
	http.HandleFunc("/api/products", getProductHandler)
	http.HandleFunc("/api/products/{id}", updateProductHandler)
	r.HandleFunc("/api/orders/place/ai", PlaceOrderH).Methods("POST")
	r.HandleFunc("/api/orders/api", GetOrders).Methods("GET")
	r.HandleFunc("/api/order/latest/ai", GetLatest).Methods("GET")
	r.HandleFunc("/api/placeOrder/ai", PlaceOrderH).Methods("POST")
	r.HandleFunc("/api/products/{name}", deleteProductByName).Methods("DELETE")
	r.HandleFunc("/api/products/{name}", UpdateProductHandler).Methods("PUT")
	r.HandleFunc("/api/dashboard", dashboardHandler).Methods("GET")
	r.HandleFunc("/api/chat", chatbotHandler).Methods("POST")
	r.HandleFunc("/api/contact", getContactInfo).Methods("GET")
	r.HandleFunc("/api/track-order", trackOrder).Methods("GET")
	r.HandleFunc("/api/complaints", addComplaint).Methods("POST")
	r.HandleFunc("/api/products", getProductsByCategory).Methods("GET")
	r.HandleFunc("/api/contact", saveContactInfo).Methods("POST")
	r.HandleFunc("/api/contact", getContactInfo).Methods("GET")
	r.HandleFunc("/api/complaints/{id}", getComplaintByID).Methods("GET")
	r.HandleFunc("/upload", uploadFormHandler).Methods("GET")

	// Handle the image upload and processing on POST request
	r.HandleFunc("/upload", handleUpload).Methods("POST")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("🌐 Web Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func serveStaticPage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	}
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "login.html")
}

func signupPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signup.html")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("name"))
	password := strings.TrimSpace(r.Form.Get("password"))
	role := strings.TrimSpace(r.Form.Get("role"))

	if username == "" || password == "" || role == "" {
		http.Error(w, "All fields are required!", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	var existing User
	err := usersCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&existing)
	if err == nil {
		http.Error(w, "Username already exists!", http.StatusBadRequest)
		return
	}

	_, err = usersCollection.InsertOne(context.TODO(), bson.M{
		"username": username,
		"password": password,
		"role":     role,
	})
	if err != nil {
		http.Error(w, "Signup failed!", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Assuming you have a /api/user/profile endpoint
func GetUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 🍪 Get username from cookie (cookie name: "userID" contains username like "gugan")
	userCookie, err := r.Cookie("userID")
	if err != nil {
		http.Error(w, "🔒 User not authenticated", http.StatusUnauthorized)
		fmt.Println("❌ userID cookie not found:", err)
		return
	}

	username := userCookie.Value
	fmt.Println("👤 Extracted username from cookie:", username)

	// 🔍 Query by username instead of ObjectID
	collection := client.Database("authdb").Collection("users")
	var user bson.M
	err = collection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		http.Error(w, "❌ User not found", http.StatusNotFound)
		fmt.Println("❌ User not found in DB:", err)
		return
	}

	// 🛡️ Hide sensitive info
	delete(user, "password")

	// ✅ Return user profile
	if err := json.NewEncoder(w).Encode(user); err != nil {
		fmt.Println("❌ Failed to encode JSON:", err)
	}
	fmt.Println("✅ Profile fetched successfully for user:", user)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("username"))
	password := strings.TrimSpace(r.Form.Get("password"))

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	conn, err := net.Dial("tcp", "localhost:8081")
	if err != nil {
		http.Error(w, "Authentication server error", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s:%s", username, password)
	message, _ := bufio.NewReader(conn).ReadString('\n')
	message = strings.TrimSpace(message)

	if strings.HasPrefix(message, "SUCCESS:") {
		roleData := strings.TrimPrefix(message, "SUCCESS:")
		parts := strings.Split(roleData, ":")
		if len(parts) != 2 {
			http.Error(w, "Invalid authentication response format", http.StatusInternalServerError)
			return
		}

		role := parts[0]
		userID := parts[1]

		log.Println("✅ Login successful. Role:", role, "UserID:", userID)
		actualUserID := parts[1] // MongoDB _id

		// ✅ Set correct cookies
		http.SetCookie(w, &http.Cookie{
			Name:  "userID",
			Value: actualUserID,
			Path:  "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "role",
			Value: fmt.Sprintf("%s:%s", role, actualUserID),
			Path:  "/",
		})
		// ✅ Set username and role cookies
		http.SetCookie(w, &http.Cookie{
			Name:  "userID",
			Value: username,
			Path:  "/",
		})

		http.SetCookie(w, &http.Cookie{
			Name:  "role",
			Value: role,
			Path:  "/",
		})

		if role == "user" {
			http.Redirect(w, r, "/dashboard.html", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/admin.html", http.StatusSeeOther)
		}
	} else {
		w.Write([]byte(`<h3 style="color: red;">Login Failed. Invalid credentials.</h3><a href="/">Try Again</a>`))
	}
}

// Product APIs
func GetAllProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cursor, err := productsCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch products", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var products []models.Product
	if err = cursor.All(context.TODO(), &products); err != nil {
		http.Error(w, "Error parsing products", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(products)
}

func AddProductHandler(w http.ResponseWriter, r *http.Request) {
	var product models.Product
	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	_, err = productsCollection.InsertOne(context.TODO(), product)
	if err != nil {
		http.Error(w, "Error adding product", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Product added successfully"})
}

// Cart APIs
func AddToCartHandler(w http.ResponseWriter, r *http.Request) {
	var product models.Product

	userCookie, err := r.Cookie("userID")
	if err != nil {
		http.Error(w, "User not logged in", http.StatusUnauthorized)
		return
	}
	roleCookie, err := r.Cookie("role")
	if err != nil {
		http.Error(w, "User role not found", http.StatusUnauthorized)
		return
	}

	userID := userCookie.Value
	roleValue := roleCookie.Value

	fmt.Println("🛒 AddToCart - UserID:", userID, "| Role:", roleValue)

	// Decode the product from request body
	err = json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		http.Error(w, "Invalid product data", http.StatusBadRequest)
		return
	}

	// Create cart item with userID
	cartItem := bson.M{
		"product_id":  product.ID.Hex(),
		"user_id":     userID, // directly from cookie
		"name":        product.Name,
		"description": product.Description,
		"price":       product.Price,
		"imageurl":    product.ImageURL,
	}

	// Insert to MongoDB
	_, err = cartCollection.InsertOne(context.Background(), cartItem)
	if err != nil {
		http.Error(w, "Failed to add to cart", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Item added to cart"})
}
func ViewCartHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 🔐 Extract user ID from cookie
	userCookie, err := r.Cookie("userID")
	if err != nil {
		http.Error(w, "🔒 User not logged in", http.StatusUnauthorized)
		return
	}
	userID := userCookie.Value
	fmt.Println("🛒 Viewing cart for UserID:", userID)

	// 🔍 Query MongoDB for cart items matching this user
	filter := bson.M{"user_id": userID}
	cursor, err := cartCollection.Find(context.TODO(), filter)
	if err != nil {
		http.Error(w, "❌ Failed to fetch cart items", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var cartItems []bson.M
	if err := cursor.All(context.TODO(), &cartItems); err != nil {
		http.Error(w, "❌ Error decoding cart items", http.StatusInternalServerError)
		return
	}

	// ✅ Return cart items
	json.NewEncoder(w).Encode(cartItems)
}

func GetOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 🔒 Extract userID from the cookie
	userCookie, err := r.Cookie("userID")
	if err != nil {
		http.Error(w, "🔒 User not authenticated", http.StatusUnauthorized)
		return
	}
	actualUserID := userCookie.Value
	fmt.Println("✅ User ID from cookie:", actualUserID)

	// 🔍 Query MongoDB for orders by userID
	collection := client.Database("authdb").Collection("orders")
	filter := bson.M{"userID": actualUserID}
	fmt.Println("🔍 Querying orders with filter:", filter)

	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		http.Error(w, "❌ Failed to fetch orders", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var orders []models.Order
	if err := cursor.All(context.TODO(), &orders); err != nil {
		http.Error(w, "❌ Error decoding orders", http.StatusInternalServerError)
		return
	}

	if len(orders) == 0 {
		fmt.Println("⚠️ No orders found for user:", actualUserID)
	} else {
		fmt.Printf("✅ Found %d orders for user: %s\n", len(orders), actualUserID)
	}

	json.NewEncoder(w).Encode(orders)
}

func GetLatestOrderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	collection := client.Database("authdb").Collection("orders")
	opts := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
	var latestOrder models.Order
	err := collection.FindOne(context.TODO(), bson.M{}, opts).Decode(&latestOrder)
	if err != nil {
		http.Error(w, "No order found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(latestOrder)
}
func PlaceOrderHandler(w http.ResponseWriter, r *http.Request) {
	var order models.Order

	// 🔒 Get user ID from cookie
	userCookie, err := r.Cookie("userID")
	if err != nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := userCookie.Value

	// 🧾 Decode order data from body
	err = json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		http.Error(w, "Invalid order data", http.StatusBadRequest)
		return
	}

	order.ID = primitive.NewObjectID()
	order.UserID = userID // 💾 Assign extracted user ID
	order.Status = "Pending"

	collection := client.Database("authdb").Collection("orders")
	_, err = collection.InsertOne(context.TODO(), order)
	if err != nil {
		http.Error(w, "Failed to place order", http.StatusInternalServerError)
		return
	}

	// 🧹 Optional: Clear cart items from DB for this user (recommended)
	_, err = cartCollection.DeleteMany(context.TODO(), bson.M{"user_id": userID})
	if err != nil {
		log.Println("⚠️ Failed to clear cart:", err)
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "✅ Order placed successfully"})
}

func ClassifyImageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "AI classification coming soon!"})
}
func getUsers(w http.ResponseWriter, r *http.Request) {
	cursor, err := usersCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var users []User
	if err = cursor.All(context.TODO(), &users); err != nil {
		http.Error(w, "Error reading users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	res, err := usersCollection.DeleteOne(context.TODO(), bson.M{"username": username})
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}
	if res.DeletedCount == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)

}
func getProductHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/products/")
	fmt.Println("Requesting product ID:", id)

	mu.Lock()
	defer mu.Unlock()

	for _, p := range products {
		fmt.Println("Checking product:", p.ID)
		if p.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(p)
			return
		}
	}

	fmt.Println("Product not found!")
	http.Error(w, "Product not found", http.StatusNotFound)
}

// Update a product
func updateProductHandler(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "PUT")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/products/")
	if id == "" || id == "null" {
		http.Error(w, "Invalid or missing product ID", http.StatusBadRequest)
		return
	}

	fmt.Printf("Request URL: %s\n", r.URL.String())
	fmt.Printf("Attempting to update product ID: %s\n", id)

	var updatedProduct Product
	if err := json.NewDecoder(r.Body).Decode(&updatedProduct); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	fmt.Printf("Received update data: %+v\n", updatedProduct)

	for i, p := range products {
		if p.ID == id {
			updatedProduct.ID = id
			products[i] = updatedProduct

			fmt.Printf("Updated product: %+v\n", products[i])

			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Product updated successfully",
			})
			return
		}
	}

	http.Error(w, "Product not found", http.StatusNotFound)
}
func GetOrders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	collection := client.Database("authdb").Collection("orders")
	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "❌ Failed to fetch orders", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var orders []models.Order
	if err := cursor.All(context.TODO(), &orders); err != nil {
		http.Error(w, "❌ Error decoding orders", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(orders)
}

func GetLatest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	collection := client.Database("authdb").Collection("orders")
	opts := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
	var latestOrder models.Order
	err := collection.FindOne(context.TODO(), bson.M{}, opts).Decode(&latestOrder)
	if err != nil {
		http.Error(w, "No order found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(latestOrder)
}

func PlaceOrderH(w http.ResponseWriter, r *http.Request) {
	var order models.Order
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		http.Error(w, "Invalid order data", http.StatusBadRequest)
		return
	}

	order.ID = primitive.NewObjectID()
	order.Status = "pending"

	collection := client.Database("authdb").Collection("orders")
	_, err = collection.InsertOne(context.TODO(), order)
	if err != nil {
		http.Error(w, "Failed to place order", http.StatusInternalServerError)
		return
	}

	// Clear cart items after successful order
	mu.Lock()
	cartItems = []models.Product{}
	mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Order placed successfully"})
}
func deleteProductByName(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	w.Header().Set("Content-Type", "application/json")

	res, err := productsCollection.DeleteOne(context.TODO(), bson.M{"name": name})
	if err != nil {
		http.Error(w, "Error deleting product", http.StatusInternalServerError)
		return
	}
	if res.DeletedCount == 0 {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Product deleted"})
}
func UpdateProductHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get the product name from the URL parameters
	params := mux.Vars(r)
	name := params["name"]

	fmt.Println("Received update request for product:", name)

	// Parse the request body to get the updated product data
	var updatedProduct models.Product
	if err := json.NewDecoder(r.Body).Decode(&updatedProduct); err != nil {
		http.Error(w, "Invalid product data", http.StatusBadRequest)
		fmt.Println("Error parsing request body:", err)
		return
	}

	// Log the received updated product details
	fmt.Printf("Updated product data: %+v\n", updatedProduct)

	// Prepare the update data to send to MongoDB
	update := bson.M{
		"$set": bson.M{
			"name": updatedProduct.Name,

			"price":       updatedProduct.Price,
			"description": updatedProduct.Description,
		},
	}

	// Perform the update operation on the product collection based on name
	result, err := productsCollection.UpdateOne(
		context.TODO(),
		bson.M{"name": name}, // Find the product by name
		update,
	)

	if err != nil {
		// Log the error to understand the failure
		fmt.Println("Error updating product:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Log the result of the update operation
	fmt.Printf("Update result: %+v\n", result)

	// If no product was matched for the given name
	if result.MatchedCount == 0 {
		fmt.Println("No product found with name:", name)
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	// Return a success message after updating the product
	response := map[string]string{"message": "Product updated successfully"}
	json.NewEncoder(w).Encode(response)
}
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCount, err := usersCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		http.Error(w, "Failed to count users", http.StatusInternalServerError)
		return
	}

	productCount, err := productsCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		http.Error(w, "Failed to count products", http.StatusInternalServerError)
		return
	}

	startOfDay := time.Now().Truncate(24 * time.Hour)
	orderCount, err := ordersCollection.CountDocuments(ctx, bson.M{
		"createdAt": bson.M{
			"$gte": startOfDay,
		},
	})
	if err != nil {
		http.Error(w, "Failed to count today's orders", http.StatusInternalServerError)
		return
	}

	data := DashboardData{
		TotalUsers:    userCount,
		TotalProducts: productCount,
		OrdersToday:   orderCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
func trackOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("order_id")
	if orderID == "" {
		http.Error(w, "Order ID is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(orderID)
	if err != nil {
		http.Error(w, "Invalid order ID format", http.StatusBadRequest)
		return
	}

	collection := client.Database("authdb").Collection("orders")
	var order bson.M // use generic map for flexibility

	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&order)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func addComplaint(w http.ResponseWriter, r *http.Request) {
	var complaint Complaint
	err := json.NewDecoder(r.Body).Decode(&complaint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	complaint.Status = "pending"
	complaint.CreatedAt = time.Now()

	collection := client.Database("authdb").Collection("complaints")
	result, err := collection.InsertOne(ctx, complaint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	complaint.ID = result.InsertedID.(primitive.ObjectID)
	json.NewEncoder(w).Encode(complaint)
}

func getProductsByCategory(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("description")
	if category == "" {
		http.Error(w, "Product description is required", http.StatusBadRequest)
		return
	}

	collection := client.Database("authdb").Collection("products")
	cursor, err := collection.Find(ctx, bson.M{
		"description": bson.M{"$regex": category, "$options": "i"},
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying the database: %v", err), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var products []Product
	if err = cursor.All(ctx, &products); err != nil {
		http.Error(w, fmt.Sprintf("Error decoding products: %v", err), http.StatusInternalServerError)
		return
	}

	if len(products) == 0 {
		http.Error(w, "No products found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(products); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
	}
}

func analyzeIntent(text string) string {
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "contact"), strings.Contains(text, "call"), strings.Contains(text, "email"), strings.Contains(text, "whatsapp"):
		return "contact"
	case strings.Contains(text, "track"), strings.Contains(text, "order"), strings.Contains(text, "delivery"):
		return "track_order"
	case strings.Contains(text, "complaint"), strings.Contains(text, "issue"), strings.Contains(text, "problem"):
		return "complaint"
	case strings.Contains(text, "product"), strings.Contains(text, "description"), strings.Contains(text, "price"):
		return "product_info"
	case strings.Contains(text, "navigate"), strings.Contains(text, "go to"), strings.Contains(text, "cart"), strings.Contains(text, "payment"):
		return "navigation"
	default:
		return "unknown"
	}
}

func correctGrammar(text string) string {
	return text // Mock grammar correction
}

func chatbotHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Message string `json:"message"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	correctedText := correctGrammar(req.Message)
	intent := analyzeIntent(correctedText)

	var response ChatMessage
	response.Time = time.Now().Format("15:04")

	switch intent {
	case "contact":
		response.Type = "bot"
		response.Content = "Here are our contact details. How would you like to reach us?"
		response.Metadata = "contact_options"
	case "track_order":
		response.Type = "bot"
		response.Content = "Please provide your order ID so I can check the status for you."
	case "complaint":
		response.Type = "bot"
		response.Content = "I'm sorry to hear about your issue. You can file a complaint and we'll respond shortly."
	case "product_info":
		response.Type = "bot"
		response.Content = "What type of product are you looking for? (e.g., phone, laptop, earphones)"
	case "navigation":
		response.Type = "bot"
		response.Content = "Where would you like to go? (Cart, Payment, Orders, Home)"
	default:
		response.Type = "bot"
		response.Content = "I'm here to help. You can ask about products, orders, complaints, or contact info."
	}

	json.NewEncoder(w).Encode(response)
}
func saveContactInfo(w http.ResponseWriter, r *http.Request) {
	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	collection := client.Database("authdb").Collection("contact")

	// Replace existing contact document or insert one if none exists
	_, err := collection.ReplaceOne(ctx, bson.M{}, contact, options.Replace().SetUpsert(true))
	if err != nil {
		http.Error(w, "Error saving contact info", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contact info saved successfully"})
}

func getContactInfo(w http.ResponseWriter, r *http.Request) {
	collection := client.Database("authdb").Collection("contact")
	var contact Contact

	err := collection.FindOne(ctx, bson.M{}).Decode(&contact)
	if err != nil {
		http.Error(w, "No contact info found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contact)
}
func getComplaintByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	idStr := vars["id"]

	objID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid complaint ID", http.StatusBadRequest)
		return
	}

	var complaint Complaint
	collection := client.Database("authdb").Collection("complaints")
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&complaint)
	if err != nil {
		http.Error(w, "Complaint not found", http.StatusNotFound)
		return
	}

	type ComplaintResponse struct {
		ID          string    `json:"id"`
		CustomerID  string    `json:"customer_id"`
		Description string    `json:"description"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
	}

	response := ComplaintResponse{
		ID:          complaint.ID.Hex(),
		CustomerID:  complaint.CustomerID,
		Description: complaint.Description,
		Status:      complaint.Status,
		CreatedAt:   complaint.CreatedAt,
	}

	json.NewEncoder(w).Encode(response)
}
func uploadFormHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/image.html")
}

// Handle the POST request to upload and process the image
func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/uploads", http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Image read error", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Decode the image
	img, format, err := image.Decode(file)
	if err != nil {
		http.Error(w, "Image decode error", http.StatusInternalServerError)
		return
	}

	// Apply the effects based on user input
	applyGray := r.FormValue("grayscale") == "on"
	applyBlur := r.FormValue("gaussian") == "on"
	applySobel := r.FormValue("sobel") == "on"

	var processed image.Image = img

	if applyGray {
		processed = toGrayscale(processed)
	}
	if applyBlur {
		if gray, ok := processed.(*image.Gray); ok {
			processed = applyGaussianBlur(gray)
		}
	}
	if applySobel {
		if gray, ok := processed.(*image.Gray); ok {
			processed = applySobelFilter(gray)
		}
	}

	// Save the processed image
	outputPath := filepath.Join("uploads", "processed_"+header.Filename)
	outFile, err := os.Create(outputPath)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	// Encode the image (either PNG or JPEG)
	if strings.ToLower(format) == "png" {
		png.Encode(outFile, processed)
	} else {
		jpeg.Encode(outFile, processed, nil)
	}

	// Respond to the user
	w.Write([]byte(fmt.Sprintf("✅ Image processed and saved at: %s", outputPath)))
}

// Convert the image to grayscale
func toGrayscale(img image.Image) *image.Gray {
	bounds := img.Bounds()
	gray := image.NewGray(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			yVal := uint8(0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8))
			gray.SetGray(x, y, color.Gray{Y: yVal})
		}
	}
	return gray
}

// Apply Gaussian blur to the image
var gaussianKernel = [3][3]float64{
	{1, 2, 1},
	{2, 4, 2},
	{1, 2, 1},
}

func applyGaussianBlur(img *image.Gray) *image.Gray {
	bounds := img.Bounds()
	result := image.NewGray(bounds)
	for y := 1; y < bounds.Max.Y-1; y++ {
		for x := 1; x < bounds.Max.X-1; x++ {
			var sum float64
			for ky := -1; ky <= 1; ky++ {
				for kx := -1; kx <= 1; kx++ {
					p := img.GrayAt(x+kx, y+ky).Y
					sum += float64(p) * gaussianKernel[ky+1][kx+1]
				}
			}
			result.SetGray(x, y, color.Gray{Y: uint8(sum / 16)})
		}
	}
	return result
}

// Sobel edge detection filter
var sobelX = [3][3]int{
	{-1, 0, 1},
	{-2, 0, 2},
	{-1, 0, 1},
}

var sobelY = [3][3]int{
	{-1, -2, -1},
	{0, 0, 0},
	{1, 2, 1},
}

func applySobelFilter(img *image.Gray) *image.Gray {
	bounds := img.Bounds()
	result := image.NewGray(bounds)
	for y := 1; y < bounds.Max.Y-1; y++ {
		for x := 1; x < bounds.Max.X-1; x++ {
			var gx, gy int
			for ky := -1; ky <= 1; ky++ {
				for kx := -1; kx <= 1; kx++ {
					val := int(img.GrayAt(x+kx, y+ky).Y)
					gx += sobelX[ky+1][kx+1] * val
					gy += sobelY[ky+1][kx+1] * val
				}
			}
			mag := math.Sqrt(float64(gx*gx + gy*gy))
			if mag > 255 {
				mag = 255
			}
			result.SetGray(x, y, color.Gray{Y: uint8(mag)})
		}
	}
	return result
}
