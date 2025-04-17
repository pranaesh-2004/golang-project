package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"go_project/models"
	"io"
	"log"
	"net"
	"net/http"
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
	mu                 sync.Mutex
	client             *mongo.Client
	usersCollection    *mongo.Collection
	ordersCollection   *mongo.Collection
	cartCollection     *mongo.Collection
	productsCollection *mongo.Collection
	cartItems          []models.Product
	products           = []Product{}
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
type Order struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID      string             `bson:"user_id" json:"user_id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description" json:"description"`
	Price       float64            `bson:"price" json:"price"`
	ImageURL    string             `bson:"imageurl" json:"imageURL"`
	Status      string             `bson:"status" json:"status"`
}
type DashboardData struct {
	TotalUsers    int64 `json:"totalUsers"`
	TotalProducts int64 `json:"totalProducts"`
	OrdersToday   int64 `json:"ordersToday"`
}

func main() {
	initDB()
	go startTCPServer()
	startWebServer()
}

func initDB() {
	var err error
	clientOptions := options.Client().ApplyURI("mongodb+srv://vgugan16:gugan2004@cluster0.qyh1fuo.mongodb.net/golang?retryWrites=true&w=majority&appName=Cluster0")
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal("❌ Failed to connect to MongoDB:", err)
	}
	if err = client.Ping(context.TODO(), nil); err != nil {
		log.Fatal("❌ MongoDB connection error:", err)
	}
	fmt.Println("✅ Connected to MongoDB!")

	db := client.Database("authdb")
	usersCollection = db.Collection("users")
	productsCollection = db.Collection("products")
	cartCollection = db.Collection("cart")
	ordersCollection = db.Collection("orders")

	fmt.Println("MongoDB connection successful")
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
