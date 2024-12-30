package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"food-system/handlers"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// 确保日志输出到标准输出
	log.SetOutput(os.Stdout)

	// 连接数据库
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Printf("Error opening database: %v", err) // 错误日志
		return
	}
	defer db.Close()

	// 创建用户表 (如果不存在)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			is_admin BOOLEAN DEFAULT FALSE
		)
	`)
	if err != nil {
		log.Printf("Error creating table: %v", err) // 错误日志
		return
	}

	// 设置处理器
	handlers.SetDB(db) // 将数据库连接传递给 handlers
	http.HandleFunc("/", handlers.HomeHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/logout", handlers.LogoutHandler)
	http.HandleFunc("/admin", handlers.AdminHandler)
	http.HandleFunc("/admin/users", handlers.AdminUsersHandler)

	// 添加静态文件服务
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// 创建 Server 实例
	srv := &http.Server{
		Addr:         ":8081",
		Handler:      nil, // 使用默认的 ServeMux
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 在独立的 goroutine 中启动服务器
	go func() {
		fmt.Println("Server started on :8081")
		log.Println("Server started on :8081") // 启动日志
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("ListenAndServe error: %v", err) // 错误日志
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	// 收到中断信号后优雅地关闭服务器
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err) // 错误日志
	}

	log.Println("Server exiting") // 退出日志
	fmt.Println("Server exiting")
}
