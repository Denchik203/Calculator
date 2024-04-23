package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	pb "github.com/Denchik203/Calculator/proto"
	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	hmacSampleSecret = "qwertyytrewq"
	timeLayout       = "2006-01-02 15:04:05"
)

var (
	db *sql.DB

	regPage, loginPage, mainPg, exprPage, configPage *template.Template
)

type User struct {
	ID             int64
	Name           string
	Password       string
	OriginPassword string
}

type Expression struct {
	Status    int64
	Expr      string
	Result    string
	StartTime string
	EndTime   string
}

func loadTemplates() {

	regPage, _ = template.ParseFiles("html/register.html")
	loginPage, _ = template.ParseFiles("html/login.html")
	mainPg, _ = template.ParseFiles("html/index.html")
	exprPage, _ = template.ParseFiles("html/expressions.html")
	configPage, _ = template.ParseFiles("html/eidtConfig.html")
}

func (u User) ComparePassword(u2 User) error {
	err := compare(u2.Password, u.OriginPassword)
	if err != nil {
		return err
	}

	return nil
}

func createTable(ctx context.Context, db *sql.DB) error {
	const usersTable = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		name TEXT UNIQUE,
		password BINARY(180)
	);
	CREATE TABLE IF NOT EXISTS expressions(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		userID INTEGER,
		expression TEXT,
		status INTEGER,
		result REAL,
		startTime TEXT,
		endTime TEXT
	);`

	if _, err := db.ExecContext(ctx, usersTable); err != nil {
		return err
	}

	return nil
}

func insertUser(ctx context.Context, db *sql.DB, user *User) (int64, error) {
	var q = `
	INSERT INTO users (name, password) values ($1, $2)
	`
	result, err := db.ExecContext(ctx, q, user.Name, user.Password)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return id, nil
}

func selectUser(ctx context.Context, db *sql.DB, name string) (User, error) {
	var (
		user User
		err  error
	)

	var q = "SELECT id, name, password FROM users WHERE name=$1"
	err = db.QueryRowContext(ctx, q, name).Scan(&user.ID, &user.Name, &user.Password)
	return user, err
}

func insertExpression(ctx context.Context, db *sql.DB, userID int64, expression string, startTime string) (int64, error) {
	var q = `
	INSERT INTO expressions (userID, expression, status, startTime, endTime) values ($1, $2, $3, $4, $5)
	`

	result, err := db.ExecContext(ctx, q, userID, expression, http.StatusProcessing, startTime, "")
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, nil
	}

	return id, nil
}

func updateExpression(ctx context.Context, db *sql.DB, id int64, result float32, endTime string, status int) error {
	var q = `
	UPDATE expressions SET result = $1, status = $2, endTime = $3 WHERE id = $4
	`

	_, err := db.ExecContext(ctx, q, result, status, endTime, id)

	return err
}

func getExpressions(db *sql.DB, userID int64) chan Expression {
	var (
		Status                   int64
		Expr, StartTime, EndTime string
		Result                   float32
		q                        = `SELECT status, expression, result, startTime, endTime FROM expressions WHERE userID = $1`
	)
	out := make(chan Expression)

	go func() {
		defer close(out)
		rows, err := db.Query(q, userID)
		if err != nil {

		}
		for rows.Next() {
			rows.Scan(&Status, &Expr, &Result, &StartTime, &EndTime)
			if Status == 102 {
				out <- Expression{Status: Status, Expr: Expr, Result: "-", StartTime: StartTime, EndTime: EndTime}
			} else {
				out <- Expression{Status: Status, Expr: Expr, Result: fmt.Sprint(Result), StartTime: StartTime, EndTime: EndTime}
			}
		}
	}()

	return out
}

func generate(s string) string {
	saltedBytes := []byte(s)
	hashedBytes, _ := bcrypt.GenerateFromPassword(saltedBytes, bcrypt.DefaultCost)
	hash := string(hashedBytes[:])
	return hash
}

func compare(hash string, s string) error {
	incoming := []byte(s)
	existing := []byte(hash)
	return bcrypt.CompareHashAndPassword(existing, incoming)
}

func getID(token string) (int64, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			panic(fmt.Errorf("unexpected signing method: %v", t.Header["alg"]))
		}

		return []byte(hmacSampleSecret), nil
	})

	if err != nil {
		return 0, err
	}

	id, _ := strconv.Atoi(parsedToken.Claims.(jwt.MapClaims)["id"].(string))

	var q = "SELECT id FROM users WHERE id=$1"
	err = db.QueryRowContext(context.TODO(), q, id).Scan(&id)

	if err != nil {
		return 0, err
	}

	return int64(id), nil
}

func newToken(id int64) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  fmt.Sprint(id),
		"nbf": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
		"iat": now.Unix(),
	})

	tokenString, err := token.SignedString([]byte(hmacSampleSecret))

	return tokenString, err
}

func checkAuthorization(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("token")
	if err != nil {
		log.Println("user not authorized")
		http.Redirect(w, r, "/register", http.StatusMovedPermanently)
		return ""
	}

	return cookie.Value
}

func Reg(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	login := r.Form["login"]
	password := r.Form["password"]
	if len(login) > 0 && len(password) == 2 {
		if password[0] != password[1] {
			regPage.Execute(w, "passwords don't match")
			return
		}

		if len(password[0]) < 8 {
			regPage.Execute(w, "password is too short")
			return
		}

		ctx := context.TODO()
		login := login[0]
		password := password[0]

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			log.Printf("register failed. %v", err)
		}

		id, err := insertUser(ctx, db, &User{Name: login, Password: generate(password)})
		if err != nil {
			tx.Rollback()
			log.Printf("register failed. %v", err)
			regPage.Execute(w, "this username is already taken")
			return
		}

		token, err := newToken(id)
		if err != nil {
			tx.Rollback()
			log.Printf("auth failed. %v", err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   token,
			Expires: time.Now().Add(time.Hour * 24),
		})

		tx.Commit()
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}

	regPage.Execute(w, nil)
}

func login(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	login := r.Form["login"]
	password := r.Form["password"]

	if len(login) > 0 && len(password) > 0 {
		login := login[0]
		password := password[0]
		ctx := context.TODO()

		user, err := selectUser(ctx, db, login)
		if err != nil {
			log.Printf("auth fail. %v", err)
			loginPage.Execute(w, "user not found")
			return
		}

		err = compare(user.Password, password)
		if err != nil {
			log.Printf("auth fail. error %v\n", err)
			loginPage.Execute(w, "incorrect password")
			return
		}

		token, err := newToken(user.ID)
		if err != nil {
			log.Println("failed to create a token")
			return
		}

		log.Printf("auth succes. user id=%d\n", user.ID)

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   token,
			Expires: time.Now().Add(time.Hour * 24),
		})

		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}

	loginPage.Execute(w, "")
}

func mainPage(w http.ResponseWriter, r *http.Request) {
	token := checkAuthorization(w, r)
	id, err := getID(token)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	}

	mainPg.Execute(w, nil)

	r.ParseForm()

	expression := r.Form["expression"]
	if len(expression) > 0 {
		ctx := context.TODO()
		expression := expression[0]

		id, err = insertExpression(ctx, db, id, expression, time.Now().Format(timeLayout))
		if err != nil {
			log.Printf("%v", err)
		}
		conn, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			log.Printf("failed to connect to calculation server. %v", err)
			return
		}

		client := pb.NewCalculatorServiceClient(conn)

		go func(id int64) {

			defer conn.Close()
			resp, err := client.Solve(ctx, &pb.ExpressionRequest{Expr: expression})
			if err != nil {
				log.Printf("%v", err)
			}

			updateExpression(ctx, db, id, resp.Result, resp.EndTime, int(resp.Status))
			if err != nil {
				log.Printf("%v", err)
			}
		}(id)
	}
}

func editConfig(w http.ResponseWriter, r *http.Request) {
	type Config struct {
		Plus         int64 `json:"+"`
		Minus        int64 `json:"-"`
		Multiple     int64 `json:"*"`
		Division     int64 `json:"/"`
		NumOfWorkers int64 `json:"NumOfWorkers"`
	}
	var cfg Config
	r.ParseForm()

	data, _ := os.ReadFile("data/config.json")
	json.Unmarshal(data, &cfg)

	conn, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		log.Printf("failed to connect to calculation server. %v", err)
		return
	}

	defer conn.Close()

	client := pb.NewCalculatorServiceClient(conn)

	if val, ok := r.Form["+"]; ok {
		newVal, err := strconv.Atoi(val[0])
		if err == nil && newVal >= 0 {
			cfg.Plus = int64(newVal)
		}
	}

	if val, ok := r.Form["-"]; ok {
		newVal, err := strconv.Atoi(val[0])
		if err == nil && newVal >= 0 {
			cfg.Minus = int64(newVal)
		}
	}

	if val, ok := r.Form["*"]; ok {
		newVal, err := strconv.Atoi(val[0])
		if err == nil && newVal >= 0 {
			cfg.Multiple = int64(newVal)
		}
	}

	if val, ok := r.Form["/"]; ok {
		newVal, err := strconv.Atoi(val[0])
		if err == nil && newVal >= 0 {
			cfg.Division = int64(newVal)
		}
	}

	if val, ok := r.Form["/"]; ok {
		newVal, err := strconv.Atoi(val[0])
		if err == nil && newVal >= 0 {
			cfg.Division = int64(newVal)
		}
	}

	if val, ok := r.Form["NumOfWorkers"]; ok {
		newVal, err := strconv.Atoi(val[0])
		if err == nil && newVal >= 0 {
			cfg.NumOfWorkers = int64(newVal)
		}
	}

	client.Update(context.TODO(), &pb.ConfigRequest{Plus: cfg.Plus, Minus: cfg.Minus, Multiple: cfg.Multiple, Division: cfg.Division, NumOfWorkers: cfg.NumOfWorkers})

	configPage.Execute(w, nil)
}

func expressionList(w http.ResponseWriter, r *http.Request) {
	var expressions = make([]Expression, 0)

	token := checkAuthorization(w, r)
	id, _ := getID(token)
	in := getExpressions(db, id)

	for expression := range in {
		expressions = append(expressions, expression)
	}

	exprPage.Execute(w, expressions)
}

func main() {
	loadTemplates()

	var err error
	ctx := context.TODO()

	db, err = sql.Open("sqlite3", "store.db")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		panic(err)
	}

	if err = createTable(ctx, db); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/register", Reg)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/", mainPage)
	mux.HandleFunc("/config", editConfig)
	mux.HandleFunc("/expressions", expressionList)

	log.Println("server started")
	http.ListenAndServe(":5000", mux)
}
