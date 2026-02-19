package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strings"
)

//go:embed static/*
var embedded embed.FS

func NewHandler() http.Handler {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))
	hasSPAIndex := true
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		hasSPAIndex = false
	}
	serveSPAIndex := func(w http.ResponseWriter, r *http.Request) {
		if hasSPAIndex {
			serveStaticFile(w, r, sub, "index.html")
			return
		}
		serveStaticFile(w, r, sub, "login.html")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || r.URL == nil {
			http.NotFound(w, r)
			return
		}

		requestPath := r.URL.Path
		switch requestPath {
		case "/web", "/web/", "/web/login":
			serveStaticFile(w, r, sub, "login.html")
			return
		case "/web/user":
			http.Redirect(w, r, "/webapp/user/plans", http.StatusTemporaryRedirect)
			return
		case "/web/admin":
			http.Redirect(w, r, "/webapp/admin/overview", http.StatusTemporaryRedirect)
			return
		case "/webapp", "/webapp/":
			serveSPAIndex(w, r)
			return
		}

		if strings.HasPrefix(requestPath, "/web/static/") {
			cloned := r.Clone(r.Context())
			u := *r.URL
			u.Path = "/" + strings.TrimPrefix(requestPath, "/web/static/")
			cloned.URL = &u
			fileServer.ServeHTTP(w, cloned)
			return
		}

		if strings.HasPrefix(requestPath, "/webapp/") {
			relPath := strings.TrimPrefix(requestPath, "/webapp/")
			relPath = strings.TrimPrefix(relPath, "/")
			if relPath == "" {
				serveSPAIndex(w, r)
				return
			}
			if strings.HasPrefix(relPath, "assets/") || strings.Contains(filepath.Base(relPath), ".") {
				cloned := r.Clone(r.Context())
				u := *r.URL
				u.Path = "/" + relPath
				cloned.URL = &u
				fileServer.ServeHTTP(w, cloned)
				return
			}
			serveSPAIndex(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func serveStaticFile(w http.ResponseWriter, r *http.Request, root fs.FS, name string) {
	content, err := fs.ReadFile(root, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ext := path.Ext(name)
	if contentType := mime.TypeByExtension(ext); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	_, _ = w.Write(content)
}
