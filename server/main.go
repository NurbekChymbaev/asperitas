package main

import (
	"fmt"
	"github.com/StephanDollberg/go-json-rest-middleware-jwt"
	"github.com/ant0ine/go-json-rest/rest"
	"log"
	"net/http"
	"sync"
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Users struct {
	sync.RWMutex
	Store map[string]*User
}

func (u *Users) RegisterHandler(w rest.ResponseWriter, r *rest.Request) {

	user := User{}
	err := r.DecodeJsonPayload(&user)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, exist := u.Store[user.Username]
	if exist {
		rest.Error(w, "already exists", http.StatusUnprocessableEntity)
		return
	}

	u.Lock()
	u.Store[user.Username] = &user
	u.Unlock()

	w.WriteJson(&user)
}

type Author struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
}

type Comment struct {
	Id      string `json:"id"`
	Body    string `json:"body"`
	Created string `json:"created"`
	Author  Author `json:"author"`
}

type Post struct {
	Id       string    `json:"id"`
	Type     string    `json:"type"`
	Title    string    `json:"title"`
	Text     string    `json:"text"`
	Url      string    `json:"url"`
	Category string    `json:"category"`
	Author   Author    `json:"author"`
	Comments []Comment `json:"comments"`
}

type Posts struct {
	sync.RWMutex
	Store map[string]*Post
}

func (p *Posts) CreatePost(w rest.ResponseWriter, r *rest.Request) {

	post := Post{}
	err := r.DecodeJsonPayload(&post)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.Lock()
	id := fmt.Sprintf("%d", len(p.Store))
	post.Id = id
	p.Store[id] = &post
	p.Unlock()
	w.WriteJson(&post)
}

func (p *Posts) CreateComment(w rest.ResponseWriter, r *rest.Request) {
	id := r.PathParam("id")
	body := r.PostFormValue("comment")

	if _, ok := p.Store[id]; !ok {
		rest.NotFound(w, r)
		return
	}

	p.Lock()
	post := p.Store[id]

	comment := Comment{}
	comment.Body = body
	comment.Id = fmt.Sprintf("%d", len(post.Comments))

	post.Comments = append(post.Comments, comment)
	p.Store[id] = post
	p.Unlock()

	w.WriteJson(post)
}

func (p *Posts) GetAllPosts(w rest.ResponseWriter, r *rest.Request) {
	p.RLock()
	posts := make([]Post, len(p.Store))
	i := 0
	for _, post := range p.Store {
		posts[i] = *post
		i++
	}
	p.RUnlock()
	w.WriteJson(&posts)
}

func (p *Posts) GetPost(w rest.ResponseWriter, r *rest.Request) {

	id := r.PathParam("id")

	p.RLock()
	if _, ok := p.Store[id]; !ok {
		rest.NotFound(w, r)
		return
	}
	post := p.Store[id]
	p.RUnlock()

	w.WriteJson(post)
}

func (p *Posts) GetCategoryPosts(w rest.ResponseWriter, r *rest.Request) {
	category := r.PathParam("category")
	p.RLock()
	var posts []Post
	for _, post := range p.Store {
		if post.Category == category {
			posts = append(posts, *post)
		}
	}
	p.RUnlock()
	w.WriteJson(&posts)
}

func main() {

	users := &Users{
		Store: map[string]*User{},
	}

	// default user
	users.Store["admin"] = &User{
		Username: "admin",
		Password: "12345678",
	}

	posts := &Posts{
		Store: map[string]*Post{},
	}

	jwtMiddleware := &jwt.JWTMiddleware{
		Key:        []byte("secret key"),
		Realm:      "jwt auth",
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string) bool {
			if _, ok := users.Store[userId]; !ok {
				return false
			}
			user := users.Store[userId]
			return userId == user.Username && password == user.Password
		}}

	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	api.Use(&rest.CorsMiddleware{
		RejectNonCorsRequests: false,
		OriginValidator: func(origin string, request *rest.Request) bool {
			return origin == "http://localhost:3001"
		},
		AllowedMethods: []string{"GET", "POST", "PUT"},
		AllowedHeaders: []string{
			"Accept", "Content-Type", "X-Custom-Header", "Origin",
		},
		AccessControlAllowCredentials: true,
		AccessControlMaxAge:           3600,
	})
	api.Use(&rest.IfMiddleware{
		Condition: func(request *rest.Request) bool {
			return false
		},
		IfTrue: jwtMiddleware,
	})

	router, err := rest.MakeRouter(
		rest.Post("/api/register", users.RegisterHandler),
		rest.Post("/api/login", jwtMiddleware.LoginHandler),
		rest.Post("/api/posts", posts.CreatePost),
		rest.Get("/api/posts/", posts.GetAllPosts),
		rest.Get("/api/post/:id", posts.GetPost),
		rest.Post("/api/post/:id", posts.CreateComment),
		rest.Get("/api/posts/:category", posts.GetCategoryPosts),
	)
	if err != nil {
		log.Fatal(err)
	}

	api.SetApp(router)
	log.Fatal(http.ListenAndServe(":8080", api.MakeHandler()))
}
