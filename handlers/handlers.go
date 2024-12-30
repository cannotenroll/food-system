package handlers

import (
	"database/sql"
	"errors"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var tmpl *template.Template

// 添加一些常量
const (
	minUsernameLength = 3
	maxUsernameLength = 50
	minPasswordLength = 8
	SessionCookieName = "session_id"
)

// 初始化一个 cookie store
var store = sessions.NewCookieStore([]byte("your-secret-key")) // 请将 "your-secret-key" 替换为一个安全的密钥

func init() {
	// 修改模板加载路径为 register/*.html
	var err error
	tmpl, err = template.ParseGlob("register/*.html")
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}
}

// SetDB 将数据库连接传递给 handlers
func SetDB(database *sql.DB) {
	db = database
}

// HomeHandler 处理首页请求
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("HomeHandler: Request received. Method: %s", r.Method)

	username, authenticated := GetSessionUser(r)

	log.Printf("HomeHandler: User: %s, Authenticated: %v", username, authenticated)

	data := struct {
		Username      string
		Authenticated bool
	}{
		Username:      username,
		Authenticated: authenticated,
	}

	tmpl.ExecuteTemplate(w, "home.html", data)

	log.Printf("HomeHandler: Response sent.")
}

// LoginHandler 处理登录请求
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("LoginHandler: Request received. Method: %s", r.Method)
	if r.Method == "GET" {
		// 添加一个数据结构来传递错误信息
		data := struct {
			Error string
		}{""}
		tmpl.ExecuteTemplate(w, "login.html", data)
		return
	} else if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		log.Printf("LoginHandler: Username: %s", username)

		// 查询用户
		var user User
		err := db.QueryRow("SELECT id, username, password, is_admin FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password, &user.IsAdmin)
		if err != nil {
			if err == sql.ErrNoRows {
				// 用户不存在
				tmpl, err := template.ParseFiles("register/login.html")
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				err = tmpl.Execute(w, map[string]interface{}{"Error": "用户名或密码错误"})
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 验证密码
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			// 密码不匹配
			tmpl, err := template.ParseFiles("register/login.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = tmpl.Execute(w, map[string]interface{}{"Error": "用户名或密码错误"})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		// 设置 session
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["authenticated"] = true
		session.Values["username"] = username
		session.Values["user_id"] = user.ID
		session.Values["is_admin"] = user.IsAdmin
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 重定向到首页
		log.Printf("LoginHandler: Redirecting to /")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// RegisterHandler 处理注册请求
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("RegisterHandler: Request received. Method: %s", r.Method)
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	log.Printf("RegisterHandler: Username: %s", username)

	// 检查用户名是否已存在
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username).Scan(&exists)
	if err != nil {
		log.Printf("RegisterHandler: Database error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		data := struct {
			Error string
		}{"用户名已存在"}
		tmpl.ExecuteTemplate(w, "register.html", data)
		log.Printf("RegisterHandler: Username already exists: %s", username)
		return
	}

	// 验证输入
	err = validateInput(username, password)
	if err != nil {
		log.Printf("RegisterHandler: Input validation error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("RegisterHandler: Password hashing error: %v", err)
		http.Error(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	// 注册用户
	var isAdminValue int
	// 这里需要根据你的逻辑来判断是否为管理员，例如从表单中获取 isAdmin 的值
	// 假设你有一个名为 isAdmin 的 bool 变量
	isAdmin := false // 示例，你需要根据实际情况修改
	if isAdmin {
		isAdminValue = 1
	} else {
		isAdminValue = 0
	}

	_, err = db.Exec("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", username, hashedPassword, isAdminValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 注册成功后重定向到登录页面
	log.Printf("RegisterHandler: Redirecting to /login")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// 新增输入验证函数
func validateInput(username, password string) error {
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return errors.New("username length must be between 3 and 50 characters")
	}
	if len(password) < minPasswordLength {
		return errors.New("password must be at least 8 characters long")
	}
	return nil
}

func GetSessionUser(r *http.Request) (string, bool) {
	session, _ := store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		username := session.Values["username"].(string)
		return username, true
	}
	return "", false
}

func SetSessionUser(w http.ResponseWriter, r *http.Request, username string) {
	// 生成唯一的 session_id (简单示例，安全性较低)
	// rand.Seed(time.Now().UnixNano())
	// sessionID := strconv.FormatInt(time.Now().UnixNano(), 10) + strconv.Itoa(rand.Intn(1000))

	// // 将 session_id 和用户名存储在 sessions 中
	// sessions[sessionID] = username

	// cookie := &http.Cookie{
	// 	Name:     SessionCookieName,
	// 	Value:    sessionID,
	// 	Path:     "/",
	// 	HttpOnly: true,
	// 	// 设置 MaxAge 或 Expires 以控制 cookie 的有效期
	// }
	// http.SetCookie(w, cookie)
	// log.Printf("SetSessionUser: Cookie set for user: %s, sessionID: %s", username, sessionID)
}

// LogoutHandler 处理退出登录请求
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("LogoutHandler: Request received. Method: %s", r.Method)
	session, _ := store.Get(r, "session-name")

	// 将 authenticated 设置为 false
	session.Values["authenticated"] = false

	// 删除其他 session 值
	delete(session.Values, "username")
	delete(session.Values, "user_id")
	delete(session.Values, "is_admin")

	// 保存更改
	session.Save(r, w)

	// 重定向到首页
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// AdminHandler 处理管理员页面请求
func AdminHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("AdminHandler: Request received. Method: %s, URL: %s", r.Method, r.URL)
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check if the user is an admin
	if isAdmin, ok := session.Values["is_admin"].(bool); !ok || !isAdmin {
		log.Printf("AdminHandler: User is not admin. isAdmin: %v", isAdmin)
		http.Error(w, "您没有权限访问此页面", http.StatusForbidden)
		return
	}

	// Redirect to the user management page
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AdminUsersHandler 处理管理员用户列表请求
func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("AdminUsersHandler: Request received. Method: %s, URL: %s", r.Method, r.URL)
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if isAdmin, ok := session.Values["is_admin"].(bool); !ok || !isAdmin {
		log.Printf("AdminUsersHandler: User is not admin. isAdmin: %v", isAdmin)
		http.Error(w, "您没有权限访问此页面", http.StatusForbidden)
		return
	}

	db, err := sql.Open("mysql", "root:123456@tcp(127.0.0.1:3306)/food_system")
	if err != nil {
		log.Printf("AdminUsersHandler: Database connection error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, username FROM users")
	if err != nil {
		log.Printf("AdminUsersHandler: Database query error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username); err != nil {
			log.Printf("AdminUsersHandler: Error scanning user: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		log.Printf("AdminUsersHandler: Error iterating over users: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("register/admin_users.html")
	if err != nil {
		log.Printf("AdminUsersHandler: Error parsing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, users)
	if err != nil {
		log.Printf("AdminUsersHandler: Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// DeleteUserHandler 处理删除用户请求
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if isAdmin, ok := session.Values["is_admin"].(bool); !ok || !isAdmin {
		http.Error(w, "您没有权限访问此页面", http.StatusForbidden)
		return
	}

	userIDStr := r.FormValue("user_id")

	// 从数据库中删除用户
	_, err = db.Exec("DELETE FROM users WHERE id = ?", userIDStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 重定向回用户列表
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AddUserHandler 处理添加用户请求
func AddUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if isAdmin, ok := session.Values["is_admin"].(bool); !ok || !isAdmin {
		http.Error(w, "您没有权限访问此页面", http.StatusForbidden)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	isAdminStr := r.FormValue("is_admin")

	// 验证输入
	if err := validateInput(username, password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	// 将用户信息添加到数据库
	var isAdmin bool
	if isAdminStr == "1" {
		isAdmin = true
	}
	_, err = db.Exec("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", username, hashedPassword, isAdmin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 重定向回用户列表
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// ResetPasswordHandler 处理重置密码请求
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if isAdmin, ok := session.Values["is_admin"].(bool); !ok || !isAdmin {
		http.Error(w, "您没有权限访问此页面", http.StatusForbidden)
		return
	}

	userIDStr := r.FormValue("user_id")
	newPassword := r.FormValue("new_password")

	// 验证新密码
	if len(newPassword) < minPasswordLength {
		http.Error(w, "password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	// 更新数据库中的密码
	_, err = db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userIDStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 重定向回用户列表
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// AdminAddUserHandler 处理添加用户请求
func AdminAddUserHandler(w http.ResponseWriter, r *http.Request) {
	// 处理添加用户的逻辑
	// 例如，验证输入、插入数据库等
	// 这里可以添加具体的实现代码
	http.Error(w, "AdminAddUserHandler not implemented", http.StatusNotImplemented)
}

// AdminDeleteUserHandler 处理删除用户请求
func AdminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// 处理删除用户的逻辑
	// 例如，从数据库中删除用户
	// 这里可以添加具体的实现代码
	http.Error(w, "AdminDeleteUserHandler not implemented", http.StatusNotImplemented)
}

// AdminResetPasswordHandler 处理重置用户密码请求
func AdminResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// 处理重置密码的逻辑
	// 例如，验证输入、更新数据库等
	// 这里可以添加具体的实现代码
	http.Error(w, "AdminResetPasswordHandler not implemented", http.StatusNotImplemented)
}

// User 结构体
type User struct {
	ID       int
	Username string
	Password string
	IsAdmin  bool
}
