// Package admin exposes the management API using the Iris Admin framework.
package admin

import (
	"github.com/kataras/iris/v12"
	"github.com/nathan77886/connkit/admin/controller"
	"github.com/nathan77886/connkit/admin/middleware"
	"github.com/nathan77886/connkit/internal/store"
)

// New constructs the Admin API; static assets are served by Nginx.
func New(s *store.Store, username, password string) (*iris.Application, error) {
	api, err := controller.New(s, username, password)
	if err != nil {
		return nil, err
	}
	app := iris.New()
	app.Use(middleware.HTTPLogger)
	app.Get("/healthz", func(ctx iris.Context) {
		db, e := s.DB.DB()
		if e != nil || db.PingContext(ctx.Request().Context()) != nil {
			ctx.StatusCode(503)
			return
		}
		_, _ = ctx.WriteString("ok\n")
	})
	app.UseRouter(func(ctx iris.Context) { ctx.SetMaxRequestBodySize(1 << 20); ctx.Next() })
	app.Post("/api/v1/auth/login", api.Login)
	app.Any("/api/v1/argo/embed/{token:string}", api.ArgoEmbed)
	app.Any("/api/v1/argo/embed/{token:string}/{path:path}", api.ArgoEmbed)
	secured := app.Party("/api/v1", api.Authenticate)
	secured.Get("/account", api.Account)
	secured.Post("/auth/logout", api.Logout)
	secured.Get("/keys", api.ListKeys)
	secured.Post("/keys", api.CreateKey)
	secured.Delete("/keys/{id:uint}", api.DeleteKey)
	secured.Put("/keys/{id:uint}", api.UpdateKey)
	secured.Get("/access", api.AccessPolicy)
	secured.Put("/access", api.SaveAccessPolicy)
	secured.Get("/calls", api.ListCalls)
	secured.Post("/connections/{id:uint}/test", api.TestConnection)
	secured.Post("/connections/{id:uint}/argo-embed", api.CreateArgoEmbed)
	secured.Get("/connections/{id:uint}/oauth", api.CloudflareStatus)
	secured.Post("/connections/{id:uint}/oauth/login", api.CloudflareLogin)
	secured.Post("/connections/{id:uint}/oauth/callback", api.CloudflareCallback)
	secured.Delete("/connections/{id:uint}/oauth", api.CloudflareDisconnect)
	secured.Get("/connections", api.ListConnections)
	secured.Post("/connections", api.SaveConnection)
	secured.Put("/connections/{id:uint}", api.SaveConnection)
	secured.Delete("/connections/{id:uint}", api.DeleteConnection)
	secured.Get("/proxies", api.ListProxies)
	secured.Post("/proxies", api.SaveProxy)
	secured.Put("/proxies/{id:uint}", api.SaveProxy)
	secured.Delete("/proxies/{id:uint}", api.DeleteProxy)
	secured.Get("/storage", api.StorageConfig)
	secured.Put("/storage", api.SaveStorageConfig)
	secured.Get("/files", api.ListFiles)
	secured.Post("/files", api.PrepareUpload)
	secured.Post("/files/{id:string}/deliver", api.DeliverFile)
	secured.Delete("/files/{id:string}", api.RemoveFile)
	return app, nil
}
