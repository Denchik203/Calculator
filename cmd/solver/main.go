package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	pb "github.com/Denchik203/Calculator/proto"
	"github.com/moxar/arithmetic"
	"google.golang.org/grpc"
)

const timeLayout = "2006-01-02 15:04:05"

var (
	config       map[rune]int64 = make(map[rune]int64)
	numOfWorkers int64          = 20
	currNum      int64          = 0
)

type Config struct {
	Plus     int64 `json:"+"`
	Minus    int64 `json:"-"`
	Multiple int64 `json:"*"`
	Division int64 `json:"/"`
}

func loadConfig(fileName string) {
	var cfg Config

	data, err := os.ReadFile("data/" + fileName)
	if err != nil {
		config['+'] = 100
		config['-'] = 100
		config['*'] = 100
		config['/'] = 100
		return
	}

	json.Unmarshal(data, &cfg)

	config['+'] = cfg.Plus
	config['-'] = cfg.Minus
	config['*'] = cfg.Multiple
	config['/'] = cfg.Division
}

type Server struct {
	pb.CalculatorServiceServer
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Solve(ctx context.Context, r *pb.ExpressionRequest) (*pb.ResultResponse, error) {
	var mux sync.Mutex
	resp := &pb.ResultResponse{Status: http.StatusProcessing}

	for currNum >= numOfWorkers {
		time.Sleep(time.Millisecond * 500)
	}

	mux.Lock()
	currNum++
	mux.Unlock()

	result, err := arithmetic.Parse(r.Expr)
	if err != nil {
		resp.Status = http.StatusBadRequest
		return resp, nil
	}

	var timeOfWorking time.Duration
	for _, i := range r.Expr {
		if _, ok := config[i]; ok {
			timeOfWorking += time.Duration(config[i]) * time.Millisecond
		}
	}

	<-time.After(timeOfWorking)

	mux.Lock()
	currNum--
	mux.Unlock()

	resp.Result = float32(result.(float64))
	resp.Status = http.StatusOK
	resp.EndTime = time.Now().Format(timeLayout)

	return resp, nil
}

func (s *Server) Update(ctx context.Context, r *pb.ConfigRequest) (*pb.Null, error) {
	config['+'] = r.Plus
	config['-'] = r.Minus
	config['*'] = r.Multiple
	config['/'] = r.Division
	numOfWorkers = r.NumOfWorkers

	cfg := []byte(fmt.Sprintf(`{ 
	"+": %d,
	"-": %d,
	"*": %d,
	"/": %d,
	"NumOfWorkers": %d
}`, config['+'], config['-'], config['*'], config['/'], numOfWorkers))
	os.WriteFile("data/config.json", cfg, 0644)

	return nil, nil
}

func main() {
	loadConfig("config.json")

	lis, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer()

	serviceServer := NewServer()

	pb.RegisterCalculatorServiceServer(grpcServer, serviceServer)
	log.Println("solver started")

	if err := grpcServer.Serve(lis); err != nil {
		panic(err)
	}
}
