package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/patrickmn/go-cache"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var VarianceTimer = 30000 * time.Millisecond
var publicKeyCache = cache.New(8*time.Hour, 8*time.Hour)

type KeycloakConfig struct {
	Url   string
	Realm string
}

type KeyCloakToken struct {
	Jti               string                 `json:"jti,omitempty"`
	Exp               int64                  `json:"exp"`
	Nbf               int64                  `json:"nbf"`
	Iat               int64                  `json:"iat"`
	Iss               string                 `json:"iss"`
	Sub               string                 `json:"sub"`
	Typ               string                 `json:"typ"`
	Azp               string                 `json:"azp,omitempty"`
	Nonce             string                 `json:"nonce,omitempty"`
	AuthTime          int64                  `json:"auth_time,omitempty"`
	SessionState      string                 `json:"session_state,omitempty"`
	Acr               string                 `json:"acr,omitempty"`
	ClientSession     string                 `json:"client_session,omitempty"`
	AllowedOrigins    []string               `json:"allowed-origins,omitempty"`
	ResourceAccess    map[string]ServiceRole `json:"resource_access,omitempty"`
	Name              string                 `json:"name"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name,omitempty"`
	FamilyName        string                 `json:"family_name,omitempty"`
	Email             string                 `json:"email,omitempty"`
	RealmAccess       ServiceRole            `json:"realm_access,omitempty"`
}

type ServiceRole struct {
	Roles []string `json:"roles"`
}

type TokenContainer struct {
	Token         *oauth2.Token
	KeyCloakToken *KeyCloakToken
}

type Certs struct {
	Keys []KeyEntry `json:"keys"`
}

type KeyEntry struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5C []string `json:"x5c"`
}

func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

type AccessCheckFunction func(tc *TokenContainer, ctx *gin.Context) bool

func AuthChain(config KeycloakConfig, accessCheckFunctions ...AccessCheckFunction) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		t := time.Now()
		varianceControl := make(chan bool, 1)

		go func() {
			tokenContainer, ok := getTokenContainer(ctx, config)
			if !ok {
				_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("No token in context"))
				varianceControl <- false
				return
			}

			if !tokenContainer.Valid() {
				_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("Invalid Token"))
				varianceControl <- false
				return
			}

			for i, fn := range accessCheckFunctions {
				if fn(tokenContainer, ctx) {
					varianceControl <- true
					break
				}

				if len(accessCheckFunctions)-1 == i {
					_ = ctx.AbortWithError(http.StatusForbidden, errors.New("Access to the Resource is forbidden"))
					varianceControl <- false
					return
				}
			}
		}()

		select {
		case ok := <-varianceControl:
			if !ok {
				glog.V(2).Infof("[Gin-OAuth] %12v %s access not allowed", time.Since(t), ctx.Request.URL.Path)
				return
			}
		case <-time.After(VarianceTimer):
			_ = ctx.AbortWithError(http.StatusGatewayTimeout, errors.New("Authorization check overtime"))
			glog.V(2).Infof("[Gin-OAuth] %12v %s overtime", time.Since(t), ctx.Request.URL.Path)
			return
		}

		glog.V(2).Infof("[Gin-OAuth] %12v %s access allowed", time.Since(t), ctx.Request.URL.Path)
	}
}

func getTokenContainer(ctx *gin.Context, config KeycloakConfig) (*TokenContainer, bool) {
	var oauthToken *oauth2.Token
	var tc *TokenContainer
	var err error

	if oauthToken, err = ExtractTokenFromRequest(ctx.Request); err != nil {
		glog.Errorf("[Gin-OAuth] Can not extract oauth2.Token, caused by: %s", err)
		return nil, false
	}
	if !oauthToken.Valid() {
		log.Print("[Gin-OAuth] Invalid Token - nil or expired")
		return nil, false
	}

	if tc, err = GetTokenContainer(ctx.Request.Context(), oauthToken, config); err != nil {
		log.Printf("[Gin-OAuth] Can not extract TokenContainer, caused by: %s", err)
		return nil, false
	}

	if IsExpired(tc.KeyCloakToken) {
		log.Print("[Gin-OAuth] Keycloak Token has expired")
		return nil, false
	}

	return tc, true
}

func ExtractTokenFromRequest(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("No authorization header")
	}

	th := strings.Split(hdr, " ")
	if len(th) != 2 {
		return nil, errors.New("Incomplete authorization header")
	}

	return &oauth2.Token{AccessToken: th[1], TokenType: th[0]}, nil
}

func ExtractTokenFromAuth(a *Auth) *oauth2.Token {
	return &oauth2.Token{AccessToken: a.AccessToken, TokenType: a.TokenType}
}

func GetTokenContainer(ctx context.Context, token *oauth2.Token, config KeycloakConfig) (*TokenContainer, error) {

	keyCloakToken, err := DecodeToken(ctx, token, config)
	if err != nil {
		return nil, err
	}

	return &TokenContainer{
		Token: &oauth2.Token{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
		},
		KeyCloakToken: keyCloakToken,
	}, nil
}

func DecodeToken(ctx context.Context, token *oauth2.Token, config KeycloakConfig) (*KeyCloakToken, error) {
	keyCloakToken := KeyCloakToken{}
	var err error
	parsedJWT, err := jwt.ParseSigned(token.AccessToken)
	if err != nil {
		glog.Errorf("[Gin-OAuth] jwt not decodable: %s", err)
		return nil, err
	}
	key, err := getPublicKey(ctx, parsedJWT.Headers[0].KeyID, config)
	if err != nil {
		glog.Errorf("Failed to get publickey %v", err)
		return nil, err
	}

	err = parsedJWT.Claims(key, &keyCloakToken)
	if err != nil {
		glog.Errorf("Failed to get claims JWT:%+v", err)
		return nil, err
	}
	return &keyCloakToken, nil
}

func IsExpired(token *KeyCloakToken) bool {
	if token.Exp == 0 {
		return false
	}
	now := time.Now()
	fromUnixTimestamp := time.Unix(token.Exp, 0)
	return now.After(fromUnixTimestamp)
}

func getPublicKey(ctx context.Context, keyId string, config KeycloakConfig) (interface{}, error) {

	keyEntry, err := getPublicKeyFromCacheOrBackend(ctx, keyId, config)
	if err != nil {
		return nil, err
	}
	if strings.ToUpper(keyEntry.Kty) == "RSA" {
		n, _ := base64.RawURLEncoding.DecodeString(keyEntry.N)
		bigN := new(big.Int)
		bigN.SetBytes(n)
		e, _ := base64.RawURLEncoding.DecodeString(keyEntry.E)
		bigE := new(big.Int)
		bigE.SetBytes(e)
		return &rsa.PublicKey{N: bigN, E: int(bigE.Int64())}, nil
	} else if strings.ToUpper(keyEntry.Kty) == "EC" {
		x, _ := base64.RawURLEncoding.DecodeString(keyEntry.X)
		bigX := new(big.Int)
		bigX.SetBytes(x)
		y, _ := base64.RawURLEncoding.DecodeString(keyEntry.Y)
		bigY := new(big.Int)
		bigY.SetBytes(y)

		var curve elliptic.Curve
		crv := strings.ToUpper(keyEntry.Crv)
		switch crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("EC curve algorithm not supported " + keyEntry.Kty)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     bigX,
			Y:     bigY,
		}, nil
	}

	return nil, errors.New("no support for keys of type " + keyEntry.Kty)
}

func getPublicKeyFromCacheOrBackend(ctx context.Context, keyId string, config KeycloakConfig) (KeyEntry, error) {
	entry, exists := publicKeyCache.Get(keyId)
	if exists {
		return entry.(KeyEntry), nil
	}

	u, err := url.Parse(config.Url)
	if err != nil {
		return KeyEntry{}, err
	}
	u.Path = path.Join(u.Path, "auth/realms/"+config.Realm+"/protocol/openid-connect/certs")

	resp, err := otelhttp.Get(ctx, u.String())
	if err != nil {
		return KeyEntry{}, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var certs Certs
	err = json.Unmarshal(body, &certs)
	if err != nil {
		return KeyEntry{}, err
	}

	for _, keyIdFromServer := range certs.Keys {
		if keyIdFromServer.Kid == keyId {
			publicKeyCache.Set(keyId, keyIdFromServer, cache.DefaultExpiration)
			return keyIdFromServer, nil
		}
	}

	return KeyEntry{}, errors.New("No public key found with kid " + keyId + " found")
}

func AuthCheck() func(tc *TokenContainer, ctx *gin.Context) bool {
	return func(tc *TokenContainer, ctx *gin.Context) bool {
		addTokenToContext(tc, ctx)
		return true
	}
}

func addTokenToContext(tc *TokenContainer, ctx *gin.Context) {
	ctx.Set("token", *tc.KeyCloakToken)
	replacedUid := strings.ReplaceAll(tc.KeyCloakToken.PreferredUsername, "service-account-", "")
	ctx.Set("uid", replacedUid)
}
