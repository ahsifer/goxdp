package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	// "net/http"
)

func (app *Application) privateRouter() *chi.Mux {
	// Create non-global registry.
	reg := prometheus.NewRegistry()

	// Add go runtime metrics and process collectors.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	chiRouter := chi.NewRouter()
	chiRouter.Use(middleware.Logger)
	chiRouter.Use(middleware.Recoverer)
	chiRouter.Use(middleware.CleanPath)
	chiRouter.Use(middleware.RealIP)
	chiRouter.Use(middleware.RedirectSlashes)
	chiRouter.Post("/load", app.xdpLoad)
	chiRouter.Post("/unload", app.xdpUnload)
	chiRouter.Post("/block", app.xdpBlock)
	chiRouter.Get("/status", app.xdpStatus)
	chiRouter.Post("/flushblocked", app.xdpBlockedFlush)
	chiRouter.Post("/flushstatus", app.xdpStatusFlush)
	return chiRouter
}

func (app *Application) publicRouter() *chi.Mux {
	// Create non-global registry.
	reg := prometheus.NewRegistry()

	// Add go runtime metrics and process collectors.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	chiRouter := chi.NewRouter()
	chiRouter.Get("/status", app.xdpStatus)
	chiRouter.Get("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}).ServeHTTP)
	return chiRouter
}
