package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	pb "github.com/Denchik203/Calculator/proto"
	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const hmacSampleSecret = "qwertyytrewq"

var (
	db *sql.DB

	regPage, loginPage, mainPg, exprPage *template.Template
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
	Result    float32
	StartTime string
	EndTime   string
}

func loadTemplates() {

	regPage, _ = template.ParseFiles("html/register.html")
	loginPage, _ = template.ParseFiles("html/login.html")
	mainPg, _ = template.ParseFiles("html/index.html")
	exprPage, _ = template.ParseFiles("html/expressions.html")
}

func (u User) ComparePassword(u2 User) error {
	err := compare(u2.Password, u.OriginPassword)
	if err != nil {
		log.Println("auth fail")
		return err
	}

	log.Println("auth success")
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

func insertExpression(ctx context.Context, db *sql.DB, userID int64, expression string) (int64, error) {
	var q = `
	ISERT INTO expressions (userID, expression, status) values ($1, $2, $3)
	`

	result, err := db.ExecContext(ctx, q, userID, expression, http.StatusProcessing)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, nil
	}

	return id, nil
}

func updateExpression(ctx context.Context, db *sql.DB, id int64, result float32, status int) error {
	var q = `
	UPDATE expressions SET result = $1, status = $2 WHERE id = $3
	`

	_, err := db.ExecContext(ctx, q, result, status, id)

	return err
}

func getExpressions(ctx context.Context, db *sql.DB, userID int64) chan Expression {
	var (
		Status                   int64
		Expr, StartTime, EndTime string
		q                        = `
		SELECT status, expression 
		`
	)
	out := make(chan Expression)

	go func() {
		defer close(out)
		rows := db.QueryRowContext(ctx, q)
		for rows.Scan(&Status, &Expr, StartTime, &EndTime) == nil {
			out <- Expression{Status: Status, Expr: Expr, StartTime: StartTime, EndTime: EndTime}
		}
	}()

	return out
}

func generate(s string) string {
	saltedBytes := []byte(s)
	hashedBytes, _ := bcrypt.GenerateFromPassword(saltedBytes, bcrypt.DefaultCost)
	log.Println(hashedBytes)
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

		log.Printf("auth succes. token=%v", token)
		tx.Commit()
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
	id, _ := getID(token)
	mainPg.Execute(w, nil)

	r.ParseForm()

	expression := r.Form["expression"]
	if len(expression) > 0 {
		ctx := context.TODO()
		expression := expression[0]

		insertExpression(ctx, db, id, expression)
		conn, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			log.Printf("failed to connect to calculation server. %v", err)
			return
		}

		defer conn.Close()

		client := pb.NewCalculatorServiceClient(conn)

		id, err := insertExpression(ctx, db, id, expression)
		if err != nil {
			log.Printf("%v", err)
			return
		}

		resp, err := client.Solve(ctx, &pb.ExpressionRequest{Expr: expression})
		if err != nil {
			log.Printf("%v", err)
		}

		updateExpression(ctx, db, id, resp.Result, int(resp.Status))
		if err != nil {
			log.Printf("%v", err)
		}
	}
}

// Доработать
/*func editConfig(w http.ResponseWriter, r *http.Request) {
	type Config struct {
		plus     int64 `json:"+"`
		minus    int64 `json:"-"`
		multiple int64 `json:"*"`
		division int64 `json:"/"`
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

	if val, ok := r.Form["+"]; ok{
		newVal, err:=strconv.Atoi(val[0])
		if err != nil && newVal>=0{
			cfg.plus = int64(newVal)
		}
	}

	if val, ok := r.Form["-"]; ok{
		newVal, err:=strconv.Atoi(val[0])
		if err != nil && newVal>=0{
			cfg.minus = int64(newVal)
		}
	}

	if val, ok := r.Form["*"]; ok{
		newVal, err:=strconv.Atoi(val[0])
		if err != nil && newVal>=0{
			cfg.multiple = int64(newVal)
		}
	}

	if val, ok := r.Form["/"]; ok{
		newVal, err:=strconv.Atoi(val[0])
		if err != nil && newVal>=0{
			cfg.division = int64(newVal)
		}
	}
} */

func expressionList(w http.ResponseWriter, r *http.Request) {
	exprPage.Execute(w, nil)
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
	// mux.HandleFunc("/config", editConfig)
	mux.HandleFunc("/expressions", expressionList)

	log.Println("server started")
	http.ListenAndServe(":5000", mux)
}
