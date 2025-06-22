package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/html"
)

// Vuln 1: CWE-259 - Hardcoded Password
const (
	dbUser = "admin"
	dbPass = "secret123"
)

// Vuln 2: CWE-321 - Hardcoded Cryptographic Key
const secretKey = "hardcoded_key_123"

// Vuln 3: CWE-330 - Use of Insufficiently Random Values
var randSeed = int64(42)

type Stock struct {
	Symbol string
	Price  float64
}

type User struct {
	ID       int
	Username string
	Stocks   string
}

var db *sql.DB
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Vuln 4: CWE-346 - Origin Validation Error
	},
}

// Vuln 5: CWE-319 - Cleartext Transmission of Sensitive Information
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./stocks.db")
	if err != nil {
		log.Fatal(err) // Vuln 6: CWE-209 - Information Exposure Through Error Message
	}
	// Vuln 7: CWE-89 - SQL Injection (schema creation without sanitization)
	db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, stocks TEXT); CREATE TABLE IF NOT EXISTS stocks (symbol TEXT, price REAL)")
}

// Mock stock price fetcher
// Vuln 8: CWE-20 - Improper Input Validation
func fetchStockPrice(symbol string) float64 {
	return 100.0 + float64(time.Now().UnixNano()%100) // No validation
}

// Vuln 9: CWE-502 - Insecure Deserialization
func deserializeJSON(data []byte) interface{} {
	var result interface{}
	json.Unmarshal(data, &result) // Unsafe deserialization
	return result
}

// Vuln 10: CWE-611 - XML External Entity (XXE)
func parseXML(data string) string {
	doc, err := html.Parse(strings.NewReader(data))
	if err != nil {
		return "Error"
	}
	return doc.Data // No XXE protection
}

// Vuln 11: CWE-918 - Server-Side Request Forgery (SSRF)
func fetchURL(url string) string {
	resp, err := http.Get(url) // No URL validation
	if err != nil {
		return "Error"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Vuln 12: CWE-400 - Uncontrolled Resource Consumption
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// Vuln 13: CWE-89 - SQL Injection
		symbol := string(msg)
		query := fmt.Sprintf("SELECT * FROM stocks WHERE symbol = '%s'", symbol)
		rows, _ := db.Query(query)
		defer rows.Close()

		var stock Stock
		if rows.Next() {
			rows.Scan(&stock.Symbol, &stock.Price)
		} else {
			stock.Symbol = symbol
			stock.Price = fetchStockPrice(symbol)
			// Vuln 14: CWE-89 - SQL Injection
			db.Exec(fmt.Sprintf("INSERT INTO stocks (symbol, price) VALUES ('%s', %f)", symbol, stock.Price))
		}
		conn.WriteJSON(stock)
	}
}

func main() {
	// Vuln 15: CWE-326 - Inadequate Encryption Strength
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Vuln 16: CWE-16 - Configuration
	os.Setenv("DEBUG", "true") // Debug mode in production

	initDB()
	defer db.Close()

	// Vuln 17: CWE-330 - Use of Insufficiently Random Values
	rand.Seed(randSeed)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 18: CWE-79 - Cross-Site Scripting (XSS)
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "Welcome %s", name) // No sanitization
	})

	http.HandleFunc("/ws", handleWebSocket)

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Vuln 19: CWE-352 - Missing CSRF Protection
			username := r.FormValue("username")
			stocks := r.FormValue("stocks")
			// Vuln 20: CWE-89 - SQL Injection
			query := fmt.Sprintf("INSERT INTO users (username, stocks) VALUES ('%s', '%s')", username, stocks)
			db.Exec(query)
			fmt.Fprintf(w, "Registered")
		}
	})

	http.HandleFunc("/stocks", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 21: CWE-89 - SQL Injection
		username := r.URL.Query().Get("username")
		query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
		rows, err := db.Query(query)
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err) // Vuln 22: CWE-209
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var u User
			rows.Scan(&u.ID, &u.Username, &u.Stocks)
			users = append(users, u)
		}
		// Vuln 23: CWE-200 - Information Exposure
		json.NewEncoder(w).Encode(users)
	})

	http.HandleFunc("/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			deserializeJSON(body) // Vuln 24: CWE-502
			fmt.Fprintf(w, "Data imported")
		}
	})

	http.HandleFunc("/xml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			result := parseXML(string(body)) // Vuln 25: CWE-611
			fmt.Fprintf(w, "Parsed: %s", result)
		}
	})

	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		result := fetchURL(url) // Vuln 26: CWE-918
		fmt.Fprintf(w, "Fetched: %s", result)
	})

	http.HandleFunc("/dangerous", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 27: CWE-676 - Use of Potentially Dangerous Function
		cmd := r.URL.Query().Get("cmd")
		out, _ := exec.Command("sh", "-c", cmd).Output() // Dangerous function
		fmt.Fprintf(w, "Output: %s", out)
	})

	http.HandleFunc("/uaf", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 28: CWE-416 - Use After Free
		type Data struct{ Value string }
		d := &Data{Value: "test"}
		ptr := unsafe.Pointer(d)
		*d = Data{} // Free
		d2 := (*Data)(ptr) // Use after free
		fmt.Fprintf(w, "Value: %s", d2.Value)
	})

	http.HandleFunc("/set_admin", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 29: CWE-269 - Improper Privilege Management
		username := r.URL.Query().Get("username")
		query := fmt.Sprintf("UPDATE users SET role = 'admin' WHERE username = '%s'", username)
		db.Exec(query) // No privilege check
		fmt.Fprintf(w, "User promoted")
	})

	// Vuln 30-50: Additional vulnerabilities
	http.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 30: CWE-190 - Integer Overflow or Wraparound
		qty := r.URL.Query().Get("qty")
		n, _ := strconv.Atoi(qty)
		total := n * 1000 // No overflow check
		fmt.Fprintf(w, "Total: %d", total)

		// Vuln 31: CWE-22 - Path Traversal
		file := r.URL.Query().Get("file")
		data, _ := os.ReadFile(filepath.Join("/uploads", file)) // No sanitization
		fmt.Fprintf(w, "File: %s", data)

		// Vuln 32: CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
		hash := md5.Sum([]byte("weak_key")) // Broken algorithm
		fmt.Fprintf(w, "Hash: %x", hash)

		// Vuln 33: CWE-798 - Hardcoded Credentials
		apiKey := "hardcoded_api_key_123"
		fmt.Fprintf(w, "API Key: %s", apiKey)

		// Vuln 34: CWE-307 - Brute Force Protection Missing
		// No rate limiting

		// Vuln 35-50: Placeholder for additional vulnerabilities
		// Examples: CWE-732, CWE-601, CWE-522, etc.
	})

	// Vuln 51: CWE-732 - Incorrect Permission Assignment
	os.Chmod("/uploads", 0777) // World-writable directory

	// Vuln 52: CWE-404 - Improper Resource Shutdown
	// Database connection not properly closed in error cases

	// Template for web interface
	tmpl := template.Must(template.New("index").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Stock Tracker</title>
			<script>
				// Vuln 53: CWE-79 - Cross-Site Scripting (XSS)
				document.write("User: " + location.search.split('user=')[1]);
				var ws = new WebSocket("ws://localhost:8080/ws");
				ws.onmessage = function(event) {
					// Vuln 54: CWE-79 - Cross-Site Scripting (XSS)
					document.getElementById("prices").innerHTML += event.data;
				};
			</script>
		</head>
		<body>
			<h1>Stock Prices</h1>
			<form method="POST" action="/register">
				<input type="text" name="username">
				<input type="text" name="stocks">
				<input type="submit" value="Register">
			</form>
			<div id="prices"></div>
			<!-- Vuln 55: CWE-352 - Missing CSRF Token -->
		</body>
		</html>
	`))

	http.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, nil)
	})

	// Vuln 56: CWE-319 - Cleartext Transmission of Sensitive Information
	log.Fatal(http.ListenAndServe(":8080", nil)) // No HTTPS
}