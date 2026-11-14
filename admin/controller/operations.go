package controller

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/nathan77886/connkit/internal/operations"
	"github.com/nathan77886/connkit/internal/store"
)

// UpdateKey changes grants, enabled state and expiry without exposing the token.
func (a *API) UpdateKey(ctx iris.Context) {
	var in struct {
		Name          *string         `json:"name"`
		Enabled       *bool           `json:"enabled"`
		ConnectionIDs *[]uint         `json:"connection_ids"`
		ExpiresAt     json.RawMessage `json:"expires_at"`
	}
	if ctx.ReadJSON(&in) != nil || in.Enabled == nil {
		fail(ctx, 400, "enabled state required")
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var row store.Key
	if a.db(ctx).First(&row, ctx.Params().GetUintDefault("id", 0)).Error != nil {
		fail(ctx, 404, "key not found")
		return
	}
	if in.ConnectionIDs != nil {
		for _, id := range *in.ConnectionIDs {
			var count int64
			if a.db(ctx).Model(&store.Connection{}).Where("id = ?", id).Count(&count).Error != nil || count != 1 {
				fail(ctx, 400, "unknown connection")
				return
			}
		}
		row.ConnectionIDs = *in.ConnectionIDs
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			fail(ctx, 400, "name required")
			return
		}
		row.Name = *in.Name
	}
	row.Enabled = *in.Enabled
	if len(in.ExpiresAt) > 0 {
		if json.Unmarshal(in.ExpiresAt, &row.ExpiresAt) != nil || (row.ExpiresAt != nil && !row.ExpiresAt.After(time.Now())) {
			fail(ctx, 400, "valid expiry required")
			return
		}
	}
	if a.db(ctx).Save(&row).Error != nil {
		fail(ctx, 500, "key update failed")
		return
	}
	respond(ctx, row)
}

func (a *API) AccessPolicy(ctx iris.Context) {
	p, err := a.s.AccessPolicy(ctx.Request().Context())
	if err != nil {
		fail(ctx, 500, "cannot load access policy")
		return
	}
	respond(ctx, p)
}
func (a *API) SaveAccessPolicy(ctx iris.Context) {
	var p store.AccessPolicy
	if ctx.ReadJSON(&p) != nil {
		fail(ctx, 400, "invalid policy")
		return
	}
	if err := a.s.SaveAccessPolicy(ctx.Request().Context(), p); err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, p)
}
func (a *API) ListCalls(ctx iris.Context) {
	before, _ := strconv.ParseUint(ctx.URLParam("before"), 10, 64)
	q := a.db(ctx).Order("id DESC").Limit(100)
	if before > 0 {
		q = q.Where("id < ?", before)
	}
	out := []store.Call{}
	if q.Find(&out).Error != nil {
		fail(ctx, 500, "call query failed")
		return
	}
	respond(ctx, out)
}
func (a *API) TestConnection(ctx iris.Context) {
	id := ctx.Params().GetUintDefault("id", 0)
	record := store.Call{Actor: "admin", ConnectionID: id, Tool: "connection_test", Status: "running"}
	if a.db(ctx).Create(&record).Error != nil {
		fail(ctx, 500, "cannot record invocation")
		return
	}
	start := time.Now()
	out, err := (&operations.Service{Store: a.s}).Run(ctx.Request().Context(), operations.Actor{Admin: true}, "connection_test", operations.Input{ConnectionID: id})
	status := "success"
	if err != nil {
		status = "error"
	}
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request().Context()), 5*time.Second)
	defer cancel()
	if a.s.DB.WithContext(saveCtx).Model(&record).Updates(map[string]any{"status": status, "duration_ms": time.Since(start).Milliseconds()}).Error != nil {
		fail(ctx, 500, "cannot record result")
		return
	}
	if err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, out)
}
