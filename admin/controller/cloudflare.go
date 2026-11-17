package controller

import (
	"context"
	"net/url"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/nathan77886/connkit/internal/cloudflaremcp"
	"github.com/nathan77886/connkit/internal/store"
)

func (a *API) CloudflareStatus(ctx iris.Context) {
	ctx.Header("Cache-Control", "no-store")
	out, err := (&cloudflaremcp.Service{Store: a.s}).Status(ctx.Request().Context(), ctx.Params().GetUintDefault("id", 0))
	if err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, out)
}

func (a *API) CloudflareLogin(ctx iris.Context) {
	ctx.Header("Cache-Control", "no-store")
	var in struct {
		RedirectURL string `json:"redirect_url"`
	}
	if ctx.ReadJSON(&in) != nil {
		fail(ctx, 400, "callback URL required")
		return
	}
	callback, err := url.Parse(in.RedirectURL)
	// A browser flow may return only to the Admin origin that initiated it.
	if err != nil || callback.Scheme+"://"+callback.Host != ctx.GetHeader("Origin") {
		fail(ctx, 400, "OAuth callback must match the Admin browser origin")
		return
	}
	c, cancel := context.WithTimeout(ctx.Request().Context(), 60*time.Second)
	defer cancel()
	authorize, err := (&cloudflaremcp.Service{Store: a.s}).Begin(c, ctx.Params().GetUintDefault("id", 0), store.Digest(bearer(ctx)), in.RedirectURL)
	if err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, iris.Map{"authorization_url": authorize})
}

func (a *API) CloudflareCallback(ctx iris.Context) {
	ctx.Header("Cache-Control", "no-store")
	var in struct {
		State  string `json:"state"`
		Code   string `json:"code"`
		Issuer string `json:"issuer"`
	}
	if ctx.ReadJSON(&in) != nil {
		fail(ctx, 400, "invalid OAuth callback")
		return
	}
	c, cancel := context.WithTimeout(ctx.Request().Context(), 40*time.Second)
	defer cancel()
	if err := (&cloudflaremcp.Service{Store: a.s}).Finish(c, ctx.Params().GetUintDefault("id", 0), store.Digest(bearer(ctx)), in.State, in.Code, in.Issuer); err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, nil)
}

func (a *API) CloudflareDisconnect(ctx iris.Context) {
	if err := (&cloudflaremcp.Service{Store: a.s}).Disconnect(ctx.Request().Context(), ctx.Params().GetUintDefault("id", 0)); err != nil {
		fail(ctx, 500, "cannot remove Cloudflare authorization")
		return
	}
	respond(ctx, nil)
}
