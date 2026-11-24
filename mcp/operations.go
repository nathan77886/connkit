package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nathan77886/connkit/internal/operations"
	"github.com/nathan77886/connkit/internal/store"
)

func registerOperations(server *sdk.Server, s *store.Store, token string, anonymous bool, caller string, service *operations.Service) {
	tools := map[string]string{
		"cloudflare_tools":      "List tools and schemas from the registered official Cloudflare MCP OAuth connection. Optional page_cursor from nextCursor. Does not prove domain or R2 permissions.",
		"cloudflare_call":       "Call an official Cloudflare MCP tool using tool_name and tool_arguments (JSON object). Follow the user task instructions and upstream OAuth permissions. Never retry an unknown outcome.",
		"cloudflare_batch_call": "Forward up to 100 Cloudflare MCP tool calls over one authenticated session. Calls run in order and return one result per call. Never retry an unknown outcome.",
		"onepanel_request":      "Call a relative 1Panel v2 API path using method and JSON body. Calls use the registered panel account permissions. Authentication and terminal endpoints are reserved. No automatic retries.",
		"onepanel_logs":         "Read bounded 1Panel container logs using container and optional limit (tail lines).",
		"onepanel_exec":         "Execute command inside a 1Panel container using container ID and command. Returns output and exit_code only after a completion marker. Never retry an unknown outcome.",
		"rdp_open":              "Open a real RDP desktop; optional width (640..1280), height (480..1024). Returns private session_id. Max lifetime 600s, idle 120s.",
		"rdp_screenshot":        "Capture real desktop PNG using connection_id and session_id; returns bounded data_base64. Retry if no frame has arrived yet.",
		"rdp_input":             "Send input using connection_id, session_id, action: mouse_move (x,y), mouse_button (x,y,button:left/right/middle,down), key (scan_code,down). No retries for unknown results.",
		"rdp_close":             "Close private RDP session using connection_id and session_id; releases backend and route.",
		"connection_test":       "Test protocol authentication through the configured route. HTTP returns the real status; successful transport alone does not prove business acceptance.",
		"db_tables":             "List tables of a registered SQLite/MySQL/PostgreSQL database.",
		"db_schema":             "Inspect columns using table and connection_id.",
		"db_query":              "Run parameterized SQL using query, params and optional limit. Statements run with the target account's permissions; the caller decides whether to read or modify. Placeholder syntax follows the target driver.",
		"db_execute":            "Execute parameterized SQL. Never automatically retry a failed or unknown mutation.",
		"ssh_exec":              "Run command on SSH target. Returns exit_code, stdout and stderr. Do not retry unknown outcomes.",
		"sftp_read":             "Read a bounded remote file at path; returns base64 bytes.",
		"https_request":         "Request a relative path under configured HTTPS base_url using method and body. Redirects are returned without following.",
		"redis_scan":            "Scan keys with optional cursor, pattern and limit; repeat returned cursor until zero.",
		"redis_read":            "Run a Redis command with args; target ACLs apply. Compatible alias of redis_command.",
		"redis_command":         "Arbitrary Redis command and args; target ACLs apply. No automatic retries.",
		"mongo_collections":     "List MongoDB collection names.",
		"mongo_find":            "Find documents using collection, optional Extended JSON filter, and limit.",
		"mongo_count":           "Count documents using collection and Extended JSON filter.",
		"mongo_aggregate":       "Run an Extended JSON pipeline, including output stages when requested. Output uses canonical Extended JSON.",
		"mongo_insert":          "Insert document (Extended JSON) into collection.",
		"mongo_update":          "Update one matching document using filter and document (update operators in Extended JSON).",
		"mongo_delete":          "Delete one matching document using collection and filter.",
		"k8s_request":           "Send an HTTP request through a Kubernetes connection to an allowed Kubernetes API path. The method, path and body are passed through; target authentication and RBAC apply.",
		"k8s_get":               "GET a Kubernetes resource, discovery endpoint, or list at path under /version, /api, or /apis. Responses are bounded; use returned continue tokens for pagination.",
		"k8s_logs":              "Read bounded pod logs using a /api/v1/namespaces/.../pods/.../log path.",
		"k8s_exec":              "Execute a command in a Kubernetes pod through the exec WebSocket. Use namespace, pod, command, optional args, container, stdin and tty; Kubernetes RBAC applies and ConnKit adds no execution restriction.",
		"k8s_apply":             "Server-side apply YAML/JSON body at an exact Kubernetes resource path; RBAC applies.",
		"k8s_delete":            "Delete an exact Kubernetes resource path; RBAC applies. No automatic retry.",
		"argo_request":          "Call a relative Argo CD API path under /api/v1 using the registered Argo credentials. Redirects are not followed; writes have no automatic retry.",
	}
	for name, description := range tools {
		sdk.AddTool(server, &sdk.Tool{Name: name, Description: description}, func(ctx context.Context, _ *sdk.CallToolRequest, in operations.Input) (*sdk.CallToolResult, any, error) {
			out, err := service.Run(ctx, operations.Actor{Token: token, Anonymous: anonymous, Caller: caller}, name, in)
			if result, ok := out.(*sdk.CallToolResult); ok && err == nil {
				return result, nil, nil
			}
			return nil, out, err
		})
	}
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			params, ok := req.GetParams().(*sdk.CallToolParamsRaw)
			if !ok {
				return next(ctx, method, req)
			}
			var in struct {
				ConnectionID uint   `json:"connection_id"`
				ID           string `json:"id"`
			}
			_ = json.Unmarshal(params.Arguments, &in)
			if in.ConnectionID == 0 && in.ID != "" {
				var file store.File
				if s.DB.WithContext(ctx).First(&file, "id = ?", in.ID).Error == nil {
					in.ConnectionID = file.ConnectionID
				}
			}
			actor := "anonymous"
			if !anonymous {
				var key store.Key
				if s.DB.WithContext(ctx).Where("digest = ?", store.Digest(token)).First(&key).Error != nil {
					return nil, errors.New("access denied")
				}
				actor = "key:" + strconv.FormatUint(uint64(key.ID), 10)
			}
			name := params.Name
			if len(name) > 100 {
				name = name[:100]
			}
			record := store.Call{Actor: actor, ConnectionID: in.ConnectionID, Tool: name, Status: "running"}
			if s.DB.WithContext(ctx).Create(&record).Error != nil {
				return nil, errors.New("cannot record tool invocation")
			}
			started := time.Now()
			result, err := next(ctx, method, req)
			status := "success"
			if err != nil {
				status = "error"
			}
			if r, ok := result.(*sdk.CallToolResult); ok && r.IsError {
				status = "error"
			}
			if ctx.Err() != nil {
				status = "unknown"
			}
			saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if s.DB.WithContext(saveCtx).Model(&record).Updates(map[string]any{"status": status, "duration_ms": time.Since(started).Milliseconds()}).Error != nil {
				return nil, errors.New("cannot record tool result; side effects may have completed, do not retry")
			}
			return result, err
		}
	})
}
