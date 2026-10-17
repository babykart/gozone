package mcpserver

import (
	"context"
	"runtime/debug"

	"github.com/babykart/gozone/internal/logger"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recoverMiddleware converts a panic in any receiving-side handler (tool,
// resource read, prompt get) into a logged INTERNAL_ERROR response.
//
// The SDK runs handlers in its own goroutines (jsonrpc2 async handling), so
// a panic there unwinds outside the HTTP middleware chain: the HTTP
// panic-recovery middleware never sees it and the whole process dies. This
// middleware is the last line of defence keeping one bad request from
// taking the server down. Tool calls surface the failure as an isError
// result carrying the stable "INTERNAL_ERROR: internal error" text (the
// same envelope as tool-level errors); other methods answer with a
// JSON-RPC error.
func recoverMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (result mcp.Result, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered in MCP handler",
					"method", method,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
				te := toolErrorf(codeInternal, "internal error")
				if method == "tools/call" {
					res := &mcp.CallToolResult{}
					res.SetError(te)
					result, err = res, nil
				} else {
					result, err = nil, te
				}
			}
		}()
		return next(ctx, method, req)
	}
}
