package controller

import (
	"context"
	"errors"
	"github.com/kataras/iris/v12"
	"github.com/nathan77886/connkit/internal/files"
	"time"
)

// StorageConfig returns non-secret fields and indicates whether credentials are configured.
func (a *API) StorageConfig(ctx iris.Context) {
	service := files.New(a.s)
	c, _, err := service.LoadConfig(ctx.Request().Context(), ctx.Request().URL.Query().Get("profile"))
	if err != nil {
		if !errors.Is(err, files.ErrNotConfigured) {
			fail(ctx, 500, "cannot load storage configuration")
			return
		}
		respond(ctx, iris.Map{"configured": false})
		return
	}
	c.AccessKey = ""
	c.SecretKey = ""
	c.SessionToken = ""
	respond(ctx, iris.Map{"configured": true, "config": c})
}

// SaveStorageConfig encrypts cloud credentials; blank credentials preserve previous values.
func (a *API) SaveStorageConfig(ctx iris.Context) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var c files.Config
	if ctx.ReadJSON(&c) != nil {
		fail(ctx, 400, "invalid storage configuration")
		return
	}
	if err := files.New(a.s).SaveConfig(ctx.Request().Context(), c); err != nil {
		fail(ctx, 400, "cannot save storage configuration; check endpoint, credentials, bucket and limits")
		return
	}
	respond(ctx, nil)
}

// PrepareUpload creates a signed upload for a registered SSH connection.
func (a *API) PrepareUpload(ctx iris.Context) {
	var in files.PrepareInput
	if ctx.ReadJSON(&in) != nil {
		fail(ctx, 400, "invalid upload request")
		return
	}
	prepared, err := files.New(a.s).Prepare(ctx.Request().Context(), files.Actor{Admin: true}, in)
	if err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, prepared)
}

// ListFiles returns the administrator's recent file transfers.
func (a *API) ListFiles(ctx iris.Context) {
	out, err := files.New(a.s).List(ctx.Request().Context(), files.Actor{Admin: true})
	if err != nil {
		fail(ctx, 500, "cannot list transfers")
		return
	}
	respond(ctx, out)
}

// DeliverFile requests target-side download; the destination is fixed at upload preparation.
func (a *API) DeliverFile(ctx iris.Context) {
	bounded, cancel := context.WithTimeout(ctx.Request().Context(), 5*time.Minute)
	defer cancel()
	out, err := files.New(a.s).Deliver(bounded, files.Actor{Admin: true}, ctx.Params().Get("id"))
	if err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, out)
}

// RemoveFile deletes a staged object without touching the file on the target.
func (a *API) RemoveFile(ctx iris.Context) {
	if err := files.New(a.s).Remove(ctx.Request().Context(), files.Actor{Admin: true}, ctx.Params().Get("id")); err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, nil)
}
