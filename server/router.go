package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	// "net/http"
)

func (app *Application) newRouter() *chi.Mux {
	chiRouter := chi.NewRouter()
	chiRouter.Use(middleware.Logger)
	chiRouter.Use(middleware.Recoverer)
	chiRouter.Post("/load", app.xdpLoad)
	chiRouter.Post("/unload", app.xdpUnload)
	chiRouter.Post("/block", app.xdpBlock)
	chiRouter.Get("/status", app.xdpStatus)
	return chiRouter
}
