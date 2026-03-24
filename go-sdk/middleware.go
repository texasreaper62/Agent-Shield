// Package agentshield provides local-only AI agent security scanning.
//
// This file contains HTTP middleware, and interface-based adapters for
// Gin and gRPC frameworks. The Gin and gRPC middleware use interface-based
// type assertions so they compile without importing external packages.
package agentshield

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// threatResponse is the JSON body returned when a threat is detected.
type threatResponse struct {
	Blocked bool     `json:"blocked"`
	Message string   `json:"message"`
	Threats []Threat `json:"threats"`
}

// HTTPMiddleware returns standard net/http middleware that scans request
// bodies for threats. If a threat is detected the request is rejected with
// HTTP 403 Forbidden and a JSON body describing the threats. Safe requests
// are passed through to the next handler unchanged.
//
// The middleware reads the full request body, scans it, and then restores
// the body so downstream handlers can read it normally.
func HTTPMiddleware(shield *Shield) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}

			// Restore the body for downstream handlers.
			r.Body = io.NopCloser(bytes.NewReader(body))

			result := shield.Scan(string(body))
			if !result.Safe {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				resp := threatResponse{
					Blocked: true,
					Message: "Request blocked by Agent Shield: threat detected",
					Threats: result.Threats,
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// --- Gin middleware via interface-based approach ---

// GinContext is a minimal interface matching *gin.Context methods used by
// the middleware. This avoids importing the gin package.
type GinContext interface {
	// GetRawData returns the request body bytes.
	GetRawData() ([]byte, error)
	// AbortWithStatusJSON stops the chain and writes a JSON response.
	AbortWithStatusJSON(code int, jsonObj interface{})
	// Next calls the next handler in the chain.
	Next()
}

// GinMiddleware returns a handler function compatible with gin.HandlerFunc.
// Because it accepts and returns interface{}, you can cast it in your Gin
// application:
//
//	router.Use(func(c *gin.Context) {
//	    agentshield.GinMiddleware(shield)(c)
//	})
//
// Or use the returned function directly — it accepts any value satisfying
// the GinContext interface.
func GinMiddleware(shield *Shield) func(GinContext) {
	return func(c GinContext) {
		body, err := c.GetRawData()
		if err != nil || len(body) == 0 {
			c.Next()
			return
		}

		result := shield.Scan(string(body))
		if !result.Safe {
			resp := threatResponse{
				Blocked: true,
				Message: "Request blocked by Agent Shield: threat detected",
				Threats: result.Threats,
			}
			c.AbortWithStatusJSON(http.StatusForbidden, resp)
			return
		}

		c.Next()
	}
}

// --- gRPC interceptor via interface-based approach ---

// GRPCServerInfo holds information about the gRPC server method being called.
// This mirrors grpc.UnaryServerInfo without importing the grpc package.
type GRPCServerInfo struct {
	// FullMethod is the full RPC method string.
	FullMethod string
	// Server is the server implementation.
	Server interface{}
}

// GRPCUnaryHandler mirrors grpc.UnaryHandler: it processes unary RPC calls.
type GRPCUnaryHandler func(ctx interface{}, req interface{}) (interface{}, error)

// GRPCInterceptor returns a unary server interceptor function for gRPC.
// It inspects the request by marshaling it to JSON and scanning the result.
// If a threat is found it returns an error.
//
// Usage with real gRPC (type-assert to grpc.UnaryServerInterceptor):
//
//	interceptor := agentshield.GRPCInterceptor(shield)
//	// In your gRPC server setup, wrap the interceptor:
//	grpc.UnaryInterceptor(func(ctx context.Context, req interface{},
//	    info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
//	    return interceptor(ctx, req,
//	        &agentshield.GRPCServerInfo{FullMethod: info.FullMethod, Server: info.Server},
//	        func(c interface{}, r interface{}) (interface{}, error) {
//	            return handler(c.(context.Context), r)
//	        })
//	})
func GRPCInterceptor(shield *Shield) func(ctx interface{}, req interface{}, info *GRPCServerInfo, handler GRPCUnaryHandler) (interface{}, error) {
	return func(ctx interface{}, req interface{}, info *GRPCServerInfo, handler GRPCUnaryHandler) (interface{}, error) {
		// Marshal request to JSON for scanning.
		data, err := json.Marshal(req)
		if err == nil && len(data) > 0 {
			result := shield.Scan(string(data))
			if !result.Safe {
				return nil, &ShieldError{
					Message: "Request blocked by Agent Shield: threat detected",
					Threats: result.Threats,
				}
			}
		}

		return handler(ctx, req)
	}
}

// ShieldError is returned when a gRPC request is blocked due to detected threats.
type ShieldError struct {
	Message string
	Threats []Threat
}

// Error implements the error interface.
func (e *ShieldError) Error() string {
	return e.Message
}
