package master

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// func (mApp *MasterAPP) MasterRouter() *chi.Mux {
// 	chiRouter := chi.NewRouter()
// 	// chiRouter.Use(middleware.Logger)
// 	chiRouter.Use(middleware.Recoverer)
// 	chiRouter.Use(middleware.CleanPath)
// 	chiRouter.Use(middleware.RealIP)
// 	chiRouter.Use(middleware.RedirectSlashes)
// 	chiRouter.Post("/block", mApp.xdpBlockAllow)
// 	chiRouter.Get("/status", mApp.xdpStatus)
// 	chiRouter.Get("/pullcounter", mApp.xdpGetPullCounter)
// 	chiRouter.Post("/flushblocked", mApp.xdpBlockedFlush)
// 	chiRouter.Post("/increment", mApp.xdpIncrementPullCounter)
// 	return chiRouter
// }

func (mApp *MasterAPP) MasterPublicRoutes(r chi.Router) {
	r.Get("/status", mApp.xdpStatus)
	r.Get("/pullcounter", mApp.xdpGetPullCounter)
}

func (mApp *MasterAPP) MasterPrivateRoutes(r chi.Router) {
	r.Use(mApp.AuthMiddleware)
	r.Post("/block", mApp.xdpBlockAllow)
	r.Post("/flushblocked", mApp.xdpBlockedFlush)
	r.Post("/increment", mApp.xdpIncrementPullCounter)
	r.Post("/reload", mApp.xdpReloadConf)
}

func (mApp *MasterAPP) MasterAllRoutes() *chi.Mux {
	// This is the default router for the entire project
	defaultRouter := chi.NewRouter()

	// Api router used to serve api requests
	apiRouter := chi.NewRouter()
	// apiRouter.Use(middleware.AllowContentType("application/json"))
	apiRouter.Use(middleware.Recoverer)
	apiRouter.Use(middleware.CleanPath)
	apiRouter.Use(middleware.RealIP)
	apiRouter.Use(middleware.RedirectSlashes)
	// apiRouter.Use()

	// Public Routes that does not require authentication
	apiRouter.Group(mApp.MasterPublicRoutes)

	// Private Routes that require authentication
	apiRouter.Group(mApp.MasterPrivateRoutes)
	defaultRouter.Mount("/", apiRouter)
	return defaultRouter
}
