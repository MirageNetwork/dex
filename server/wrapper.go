package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func InitDexServer(ctx context.Context, c Config, r *mux.Router) (*Server, error) {
	rotationStrategy := defaultRotationStrategy(
		value(c.RotateKeysAfter, 6*time.Hour),
		value(c.IDTokensValidFor, 24*time.Hour),
	)

	issuerURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}

	if c.Storage == nil {
		return nil, errors.New("server: storage cannot be nil")
	}

	if len(c.SupportedResponseTypes) == 0 {
		c.SupportedResponseTypes = []string{responseTypeCode}
	}

	supportedGrant := []string{grantTypeAuthorizationCode, grantTypeRefreshToken, grantTypeDeviceCode} // default
	supportedRes := make(map[string]bool)

	for _, respType := range c.SupportedResponseTypes {
		switch respType {
		case responseTypeCode, responseTypeIDToken:
			// continue
		case responseTypeToken:
			// response_type=token is an implicit flow, let's add it to the discovery info
			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1
			supportedGrant = append(supportedGrant, grantTypeImplicit)
		default:
			return nil, fmt.Errorf("unsupported response_type %q", respType)
		}
		supportedRes[respType] = true
	}

	if c.PasswordConnector != "" {
		supportedGrant = append(supportedGrant, grantTypePassword)
	}

	sort.Strings(supportedGrant)

	now := c.Now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		issuerURL:              *issuerURL,
		connectors:             make(map[string]Connector),
		storage:                newKeyCacher(c.Storage, now),
		supportedResponseTypes: supportedRes,
		supportedGrantTypes:    supportedGrant,
		idTokensValidFor:       value(c.IDTokensValidFor, 24*time.Hour),
		authRequestsValidFor:   value(c.AuthRequestsValidFor, 24*time.Hour),
		deviceRequestsValidFor: value(c.DeviceRequestsValidFor, 5*time.Minute),
		refreshTokenPolicy:     c.RefreshTokenPolicy,
		skipApproval:           c.SkipApprovalScreen,
		alwaysShowLogin:        c.AlwaysShowLoginScreen,
		now:                    now,
		passwordConnector:      c.PasswordConnector,
		logger:                 c.Logger,
	}

	// Retrieves connector objects in backend storage. This list includes the static connectors
	// defined in the ConfigMap and dynamic connectors retrieved from the storage.
	storageConnectors, err := c.Storage.ListConnectors()
	if err != nil {
		return nil, fmt.Errorf("server: failed to list connector objects from storage: %v", err)
	}

	if len(storageConnectors) == 0 && len(s.connectors) == 0 {
		return nil, errors.New("server: no connectors specified")
	}

	for _, conn := range storageConnectors {
		if _, err := s.OpenConnector(conn); err != nil {
			return nil, fmt.Errorf("server: Failed to open connector %s: %v", conn.ID, err)
		}
	}

	// Add static connectors defined in the ConfigMap.
	instrumentHandlerCounter := func(_ string, handler http.Handler) http.HandlerFunc {
		return handler.ServeHTTP
	}
	handle := func(p string, h http.Handler) {
		r.Handle(path.Join(issuerURL.Path, p), instrumentHandlerCounter(p, h))
	}
	handleFunc := func(p string, h http.HandlerFunc) {
		handle(p, h)
	}
	handleWithCORS := func(p string, h http.HandlerFunc) {
		var handler http.Handler = h
		if len(c.AllowedOrigins) > 0 {
			allowedHeaders := []string{
				"Authorization",
			}
			cors := handlers.CORS(
				handlers.AllowedOrigins(c.AllowedOrigins),
				handlers.AllowedHeaders(allowedHeaders),
			)
			handler = cors(handler)
		}
		r.Handle(path.Join(issuerURL.Path, p), instrumentHandlerCounter(p, handler))
	}
	r.NotFoundHandler = http.NotFoundHandler()

	discoveryHandler, err := s.discoveryHandler()
	if err != nil {
		return nil, err
	}
	handleWithCORS("/.well-known/openid-configuration", discoveryHandler)

	// TODO(ericchiang): rate limit certain paths based on IP.
	handleWithCORS("/token", s.handleToken)
	handleWithCORS("/keys", s.handlePublicKeys)
	handleWithCORS("/userinfo", s.handleUserInfo)
	handleFunc("/auth", s.handleAuthorization)
	handleFunc("/auth/{connector}", s.handleConnectorLogin)
	handleFunc("/auth/{connector}/login", s.handlePasswordLogin)
	handleFunc("/device", s.handleDeviceExchange)
	handleFunc("/device/auth/verify_code", s.verifyUserCode)
	handleFunc("/device/code", s.handleDeviceCode)
	// TODO(nabokihms): "/device/token" endpoint is deprecated, consider using /token endpoint instead
	handleFunc("/device/token", s.handleDeviceTokenDeprecated)
	handleFunc(deviceCallbackURI, s.handleDeviceCallback)
	r.HandleFunc(path.Join(issuerURL.Path, "/callback"), func(w http.ResponseWriter, r *http.Request) {
		// Strip the X-Remote-* headers to prevent security issues on
		// misconfigured authproxy connector setups.
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-remote-") {
				r.Header.Del(key)
			}
		}
		s.handleConnectorCallback(w, r)
	})
	// For easier connector-specific web server configuration, e.g. for the
	// "authproxy" connector.
	handleFunc("/callback/{connector}", s.handleConnectorCallback)
	handleFunc("/approval", s.handleApproval)

	s.startKeyRotation(ctx, rotationStrategy, now)
	s.startGarbageCollection(ctx, value(c.GCFrequency, 5*time.Minute), now)

	return s, nil
}
