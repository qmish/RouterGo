package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"router-go/internal/config"
	"router-go/internal/logger"
	"router-go/internal/observability"

	"github.com/gin-gonic/gin"
)

const (
	roleAdmin = "admin"
	roleOps   = "ops"
	roleRead  = "read"
)

func AuthMiddleware(cfg config.SecurityConfig, log *logger.Logger) gin.HandlerFunc {
	roles := map[string]string{}
	var hashedTokens []hashedToken
	allowedNets := parseAllowedCIDRs(cfg.AllowedCIDRs)
	allowlistEnabled := len(cfg.AllowedCIDRs) > 0
	for _, token := range cfg.Tokens {
		value := config.ResolveSecret(token.Value)
		if value == "" || token.Role == "" {
			continue
		}
		role := strings.ToLower(token.Role)
		if strings.HasPrefix(value, "sha256:") {
			decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
			if err != nil || len(decoded) == 0 {
				continue
			}
			hashedTokens = append(hashedTokens, hashedToken{role: role, hash: decoded})
			continue
		}
		roles[value] = role
	}
	return func(c *gin.Context) {
		if !cfg.Enabled || !cfg.RequireAuth {
			if allowlistEnabled {
				if len(allowedNets) == 0 {
					c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "allowlist not configured"})
					return
				}
				if !ipAllowed(allowedNets, c.ClientIP()) {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
					return
				}
			}
			c.Set("role", roleAdmin)
			c.Next()
			return
		}
		if allowlistEnabled {
			if len(allowedNets) == 0 {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "allowlist not configured"})
				return
			}
			if !ipAllowed(allowedNets, c.ClientIP()) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
		}
		if len(roles) == 0 && len(hashedTokens) == 0 {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "auth not configured"})
			return
		}
		token := strings.TrimSpace(c.GetHeader("X-API-Key"))
		if token == "" {
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				token = strings.TrimSpace(auth[7:])
			}
		}
		role, ok := roles[token]
		if !ok && token != "" && len(hashedTokens) > 0 {
			sum := sha256.Sum256([]byte(token))
			for _, entry := range hashedTokens {
				if subtle.ConstantTimeCompare(entry.hash, sum[:]) == 1 {
					role = entry.role
					ok = true
					break
				}
			}
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if log != nil {
			log.Debug("auth ok", map[string]any{"role": role, "path": c.FullPath()})
		}
		c.Set("role", role)
		c.Next()
	}
}

func RequireRole(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, ok := c.Get("role")
		if !ok {
			c.Next()
			return
		}
		role := v.(string)
		if !roleAllowed(role, required) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func AuditMiddleware(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if log == nil {
			return
		}
		if c.Request.Method == http.MethodGet {
			return
		}
		role := roleRead
		if v, ok := c.Get("role"); ok {
			role = v.(string)
		}
		log.Info("audit", map[string]any{
			"method": c.Request.Method,
			"path":   c.FullPath(),
			"status": c.Writer.Status(),
			"role":   role,
		})
	}
}

func TraceMiddleware(store *observability.Store) gin.HandlerFunc {
	if store == nil {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	return func(c *gin.Context) {
		start := time.Now()
		traceID := strings.TrimSpace(c.GetHeader("X-Trace-Id"))
		if traceID == "" {
			traceID = generateTraceID()
		}
		c.Set("trace_id", traceID)
		c.Header("X-Trace-Id", traceID)
		c.Next()

		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		store.Add(observability.Trace{
			ID:         traceID,
			Method:     c.Request.Method,
			Path:       path,
			Status:     c.Writer.Status(),
			DurationMs: time.Since(start).Milliseconds(),
			Timestamp:  time.Now().Unix(),
			ClientIP:   c.ClientIP(),
		})
	}
}

func generateTraceID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(buf)
}

func roleAllowed(actual string, required string) bool {
	return roleOrder(strings.ToLower(actual)) >= roleOrder(strings.ToLower(required))
}

func roleOrder(role string) int {
	switch role {
	case roleRead:
		return 1
	case roleOps:
		return 2
	case roleAdmin:
		return 3
	default:
		return 0
	}
}

type hashedToken struct {
	role string
	hash []byte
}

func parseAllowedCIDRs(list []string) []*net.IPNet {
	if len(list) == 0 {
		return nil
	}
	nets := make([]*net.IPNet, 0, len(list))
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, parsed, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		nets = append(nets, parsed)
	}
	return nets
}

func ipAllowed(nets []*net.IPNet, clientIP string) bool {
	if len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false
	}
	for _, block := range nets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
