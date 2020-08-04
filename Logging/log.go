package Logging

import (
	"io"
	"log"
	"os"
)

var info *log.Logger

func init() {
	file, err := os.OpenFile("./log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Failed to open error log file:", err)
	}
	info = log.New(io.MultiWriter(file, os.Stderr), "INFO: ", log.Ldate|log.Ltime)
}

func Println(a ...interface{}) {
	info.Println(a)
}

