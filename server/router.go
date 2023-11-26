package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v2"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	// "net/http"
)

func (app *Application) newRouter() *chi.Mux {
	logger := httplog.NewLogger("httplog-example", httplog.Options{
		// JSON:             true,
		LogLevel:         slog.LevelInfo,
		Concise:          true,
		RequestHeaders:   true,
		MessageFieldName: "message",

		TimeFieldFormat: time.RFC850,
		Tags: map[string]string{
			"env": "prod",
		},
		// QuietDownPeriod: 10 * time.Second,
		// JSON: true,

		// SourceFieldName: "source",
	})
	// Create non-global registry.
	reg := prometheus.NewRegistry()

	// Add go runtime metrics and process collectors.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	chiRouter := chi.NewRouter()
	// chiRouter.Use(middleware.Logger)
	chiRouter.Use(httplog.RequestLogger(logger, []string{"/ping"}))
	chiRouter.Use(middleware.Recoverer)
	chiRouter.Post("/load", app.xdpLoad)
	chiRouter.Post("/unload", app.xdpUnload)
	chiRouter.Post("/block", app.xdpBlock)
	chiRouter.Get("/status", app.xdpStatus)
	chiRouter.Get("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}).ServeHTTP)
	return chiRouter
}
