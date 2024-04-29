/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	services "github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/coreos/go-oidc"
	oauth2 "github.com/coreos/go-oidc/oauth2"
)

// TODO(nurof3n) we need a proper implementation of this interface, see the flow
// in github.go and consult Keycloak OIDC documentation
type OIDCService interface {
	CreateOIDCAuthRequest(a *Server, ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error)
	ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*OIDCAuthResponse, error)
}

var errOIDCNotImplemented = &trace.AccessDeniedError{Message: "OIDC is only available in enterprise subscriptions"}

// UpsertOIDCConnector creates or updates an OIDC connector.
func (a *Server) UpsertOIDCConnector(ctx context.Context, connector types.OIDCConnector) (types.OIDCConnector, error) {
	upserted, err := a.Services.UpsertOIDCConnector(ctx, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorCreate{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorCreatedEvent,
			Code: events.OIDCConnectorCreatedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit OIDC connector create event.")
	}

	return upserted, nil
}

// UpdateOIDCConnector updates an existing OIDC connector.
func (a *Server) UpdateOIDCConnector(ctx context.Context, connector types.OIDCConnector) (types.OIDCConnector, error) {
	updated, err := a.Services.UpdateOIDCConnector(ctx, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorUpdate{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorUpdatedEvent,
			Code: events.OIDCConnectorUpdatedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit OIDC connector update event.")
	}

	return updated, nil
}

// CreateOIDCConnector creates a new OIDC connector.
func (a *Server) CreateOIDCConnector(ctx context.Context, connector types.OIDCConnector) (types.OIDCConnector, error) {
	created, err := a.Services.CreateOIDCConnector(ctx, connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorCreate{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorCreatedEvent,
			Code: events.OIDCConnectorCreatedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit OIDC connector create event.")
	}

	return created, nil
}

// DeleteOIDCConnector deletes an OIDC connector by name.
func (a *Server) DeleteOIDCConnector(ctx context.Context, connectorName string) error {
	if err := a.Services.DeleteOIDCConnector(ctx, connectorName); err != nil {
		return trace.Wrap(err)
	}
	if err := a.emitter.EmitAuditEvent(ctx, &apievents.OIDCConnectorDelete{
		Metadata: apievents.Metadata{
			Type: events.OIDCConnectorDeletedEvent,
			Code: events.OIDCConnectorDeletedCode,
		},
		UserMetadata: authz.ClientUserMetadata(ctx),
		ResourceMetadata: apievents.ResourceMetadata{
			Name: connectorName,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit OIDC connector delete event.")
	}
	return nil
}

func (a *Server) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	if a.oidcAuthService == nil {
		return nil, errOIDCNotImplemented
	}

	rq, err := a.oidcAuthService.CreateOIDCAuthRequest(a, ctx, req)
	return rq, trace.Wrap(err)
}

func (a *Server) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*OIDCAuthResponse, error) {
	if a.oidcAuthService == nil {
		return nil, errOIDCNotImplemented
	}

	resp, err := a.oidcAuthService.ValidateOIDCAuthCallback(ctx, q)
	return resp, trace.Wrap(err)
}

// OIDCAuthResponse is returned when auth server validated callback parameters
// returned from OIDC provider
type OIDCAuthResponse struct {
	// Username is authenticated teleport username
	Username string `json:"username"`
	// Identity contains validated OIDC identity
	Identity types.ExternalIdentity `json:"identity"`
	// Web session will be generated by auth server if requested in OIDCAuthRequest
	Session types.WebSession `json:"session,omitempty"`
	// Cert will be generated by certificate authority
	Cert []byte `json:"cert,omitempty"`
	// TLSCert is PEM encoded TLS certificate
	TLSCert []byte `json:"tls_cert,omitempty"`
	// Req is original oidc auth request
	Req OIDCAuthRequest `json:"req"`
	// HostSigners is a list of signing host public keys
	// trusted by proxy, used in console login
	HostSigners []types.CertAuthority `json:"host_signers"`
}

// OIDCAuthRequest is an OIDC auth request that supports standard json marshaling.
type OIDCAuthRequest struct {
	// ConnectorID is ID of OIDC connector this request uses
	ConnectorID string `json:"connector_id"`
	// CSRFToken is associated with user web session token
	CSRFToken string `json:"csrf_token"`
	// PublicKey is an optional public key, users want these
	// keys to be signed by auth servers user CA in case
	// of successful auth
	PublicKey []byte `json:"public_key"`
	// CreateWebSession indicates if user wants to generate a web
	// session after successful authentication
	CreateWebSession bool `json:"create_web_session"`
	// ClientRedirectURL is a URL client wants to be redirected
	// after successful authentication
	ClientRedirectURL string `json:"client_redirect_url"`
}

// ValidateOIDCAuthCallbackReq is the request made by the proxy to validate
// and activate a login via OIDC.
type ValidateOIDCAuthCallbackReq struct {
	Query url.Values `json:"query"`
}

// OIDCAuthRawResponse is returned when auth server validated callback parameters
// returned from OIDC provider
type OIDCAuthRawResponse struct {
	// Username is authenticated teleport username
	Username string `json:"username"`
	// Identity contains validated OIDC identity
	Identity types.ExternalIdentity `json:"identity"`
	// Web session will be generated by auth server if requested in OIDCAuthRequest
	Session json.RawMessage `json:"session,omitempty"`
	// Cert will be generated by certificate authority
	Cert []byte `json:"cert,omitempty"`
	// TLSCert is PEM encoded TLS certificate
	TLSCert []byte `json:"tls_cert,omitempty"`
	// Req is original oidc auth request
	Req OIDCAuthRequest `json:"req"`
	// HostSigners is a list of signing host public keys
	// trusted by proxy, used in console login
	HostSigners []json.RawMessage `json:"host_signers"`
}

// OIDCServiceImpl implements OIDCService interface, i.e., it defines the
// functions CreateOIDCAuthRequest and ValidateOIDCAuthCallback.
type OIDCServiceImpl struct {
	server *Server
}

// newOidcService creates a new OIDC service implementation
func newOidcService(a *Server) (*OIDCServiceImpl, error) {
	return &OIDCServiceImpl{
		server: a,
	}, nil
}

func (o *OIDCServiceImpl) CreateOIDCAuthRequest(a *Server, ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, client, err := o.server.getOidcConnectorAndClient(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if hook := OIDCAuthRequestHook; hook != nil {
		if err := hook(ctx, &req, connector); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	req.StateToken, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.RedirectURL = client.AuthCodeURL(req.StateToken, "", "")
	//TODO(nurof3n): see if there are any other fields in req that need to be set
	log.WithFields(logrus.Fields{teleport.ComponentKey: "oidc"}).Debugf(
		"Redirect URL: %v.", req.RedirectURL)
	err = a.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (a *Server) getOidcConnectorAndClient(ctx context.Context, request types.OIDCAuthRequest) (types.OIDCConnector, *oauth2.Client, error) {
	if request.SSOTestFlow {
		if request.ConnectorSpec == nil {
			return nil, nil, trace.BadParameter("ConnectorSpec cannot be nil when SSOTestFlow is true")
		}

		if request.ConnectorID == "" {
			return nil, nil, trace.BadParameter("ConnectorID cannot be empty")
		}

		// stateless test flow
		connector, err := services.NewOidcConnector(request.ConnectorID, *request.ConnectorSpec)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		// construct client directly
		config := newOIDCOAuth2Config(connector)
		client, err := oauth2.NewClient(http.DefaultClient, config)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		return connector, client, nil
	}

	// regular execution flow
	connector, err := a.GetOIDCConnector(ctx, request.ConnectorID, true)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	connector, err = services.InitOIDCConnector(connector)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	client, err := a.getOIDCOAuth2Client(connector)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return connector, client, nil
}

func newOIDCOAuth2Config(connector types.OIDCConnector) oauth2.Config {
	return oauth2.Config{
		Credentials: oauth2.ClientCredentials{
			ID:     connector.GetClientID(),
			Secret: connector.GetClientSecret(),
		},
		//TODO(nurof3n): see how we can manage multiple redirect URLs
		RedirectURL: connector.GetRedirectURLs()[0],
		Scope: []string{
			oidc.ScopeOpenID,
			// Keycloak specific I guess
			"profile",
			"email",
		},
		//TODO(nurof3n): remove hardcoding of endpoint
		AuthURL:  fmt.Sprintf("%s/%s", connector.GetIssuerURL(), KeycloakAuthPath),
		TokenURL: fmt.Sprintf("%s/%s", connector.GetIssuerURL(), KeycloakTokenPath),
	}
}

func (a *Server) getOIDCOAuth2Client(connector types.OIDCConnector) (*oauth2.Client, error) {
	config := newOIDCOAuth2Config(connector)

	a.lock.Lock()
	defer a.lock.Unlock()

	cachedClient, ok := a.oidcClients[connector.GetName()]
	if ok && oauth2ConfigsEqual(cachedClient.config, config) {
		return cachedClient.client, nil
	}

	delete(a.oidcClients, connector.GetName())
	client, err := oauth2.NewClient(http.DefaultClient, config)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	a.oidcClients[connector.GetName()] = &oidcClient{
		client: client,
		config: config,
	}
	return client, nil
}

type oidcManager interface {
	validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*OIDCAuthResponse, error)
}

func (o *OIDCServiceImpl) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*OIDCAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindOIDC, o.server)
	return validateOIDCAuthCallbackHelper(ctx, o.server, diagCtx, q, o.server.emitter)
}

func validateOIDCAuthCallbackHelper(ctx context.Context, m oidcManager, diagCtx *SSODiagContext, q url.Values, emitter apievents.Emitter) (*OIDCAuthResponse, error) {
	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodOIDC,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	auth, err := m.validateOIDCAuthCallback(ctx, diagCtx, q)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	claims := diagCtx.Info.OIDCClaims
	if claims != nil {
		//TODO(nurof3n): check if any claims are of interest for event.IdentityAttributes
	}

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if err := emitter.EmitAuditEvent(ctx, event); err != nil {
			log.WithError(err).Warn("Failed to emit OIDC login failed event.")
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = auth.Username

	if err := emitter.EmitAuditEvent(ctx, event); err != nil {
		log.WithError(err).Warn("Failed to emit OIDC login event.")
	}

	return auth, nil
}

func (a *Server) validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*OIDCAuthResponse, error) {
	logger := log.WithFields(logrus.Fields{teleport.ComponentKey: "github"})

	if errParam := q.Get("error"); errParam != "" {
		// try to find request so the error gets logged against it.
		state := q.Get("state")
		if state != "" {
			diagCtx.RequestID = state
			req, err := a.Services.GetOIDCAuthRequest(ctx, state)
			if err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}

		// optional parameter: error_description
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2(oauth2.ErrorInvalidRequest, errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "OIDC returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2(oauth2.ErrorInvalidRequest, "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from GitHub.")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2(oauth2.ErrorInvalidRequest, "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from GitHub.")
	}
	diagCtx.RequestID = stateToken

	req, err := a.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC Auth Request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	connector, client, err := a.getOidcConnectorAndClient(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC connector and client.")
	}

	// exchange the authorization code received by the callback for an access token
	token, err := client.RequestToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		return nil, trace.Wrap(err, "Requesting OIDC OAuth2 token failed.")
	}

	logger.Debugf("Obtained OAuth2 token: Type=%v Expires=%v Scope=%v.",
		token.TokenType, token.Expires, token.Scope)

	// TODO(bogdan) OIDC
	// 1: create a new OIDC client and get data from the provider
	// maybe using the /userinfo endpoint

	// 2: parse resp from Claims to CreateOIDCParams

	// 3: create user with CreateOIDCParams

	// 4. SSO Test Flow

	return nil, trace.NotImplemented("TODO")
}

const (
	// KeycloakuthPath is the Keycloak OIDC authorization endpoint
	KeycloakAuthPath = "protocol/openid-connect/auth"

	// KeycloakTokenPath is the Keycloak token exchange endpoint
	KeycloakTokenPath = "protocol/openid-connect/token"
)
