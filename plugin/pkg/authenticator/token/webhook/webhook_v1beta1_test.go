/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

<<<<<<< HEAD
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
	authenticationv1 "k8s.io/api/authentication/v1"
=======
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/authentication/user"
	v1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
// V1Service mocks a remote authentication service.
type V1Service interface {
	// Review looks at the TokenReviewSpec and provides an authentication
	// response in the TokenReviewStatus.
	Review(*authenticationv1.TokenReview)
	HTTPStatusCode() int
}

// NewV1TestServer wraps a V1Service as an httptest.Server.
func NewV1TestServer(s V1Service, cert, key, caCert []byte) (*httptest.Server, error) {
=======
>>>>>>> k8s/release-1.23
var apiAuds = authenticator.Audiences{"api"}

// V1beta1Service mocks a remote authentication service.
type V1beta1Service interface {
	// Review looks at the TokenReviewSpec and provides an authentication
	// response in the TokenReviewStatus.
	Review(*authenticationv1beta1.TokenReview)
	HTTPStatusCode() int
}

// NewV1beta1TestServer wraps a V1beta1Service as an httptest.Server.
func NewV1beta1TestServer(s V1beta1Service, cert, key, caCert []byte) (*httptest.Server, error) {
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	const webhookPath = "/testserver"
	var tlsConfig *tls.Config
	if cert != nil {
		cert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	if caCert != nil {
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caCert)
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.ClientCAs = rootCAs
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	serveHTTP := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, fmt.Sprintf("unexpected method: %v", r.Method), http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != webhookPath {
			http.Error(w, fmt.Sprintf("unexpected path: %v", r.URL.Path), http.StatusNotFound)
			return
		}

<<<<<<< HEAD
		var review authenticationv1beta1.TokenReview
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
		var review authenticationv1.TokenReview
=======
		var review authenticationv1beta1.TokenReview
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
		bodyData, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(bodyData, &review); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode body: %v", err), http.StatusBadRequest)
			return
		}
		// ensure we received the serialized tokenreview as expected
<<<<<<< HEAD
		if review.APIVersion != "authentication.k8s.io/v1beta1" {
=======
		if review.APIVersion != "authentication.k8s.io/v1" {
>>>>>>> k8s/release-1.23
			http.Error(w, fmt.Sprintf("wrong api version: %s", string(bodyData)), http.StatusBadRequest)
			return
		}
		// once we have a successful request, always call the review to record that we were called
		s.Review(&review)
		if s.HTTPStatusCode() < 200 || s.HTTPStatusCode() >= 300 {
			http.Error(w, "HTTP Error", s.HTTPStatusCode())
			return
		}
		type userInfo struct {
			Username string              `json:"username"`
			UID      string              `json:"uid"`
			Groups   []string            `json:"groups"`
			Extra    map[string][]string `json:"extra"`
		}
		type status struct {
			Authenticated bool     `json:"authenticated"`
			User          userInfo `json:"user"`
			Audiences     []string `json:"audiences"`
		}

		var extra map[string][]string
		if review.Status.User.Extra != nil {
			extra = map[string][]string{}
			for k, v := range review.Status.User.Extra {
				extra[k] = v
			}
		}

		resp := struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
			Status     status `json:"status"`
		}{
			Kind:       "TokenReview",
<<<<<<< HEAD
			APIVersion: authenticationv1beta1.SchemeGroupVersion.String(),
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
=======
			APIVersion: authenticationv1beta1.SchemeGroupVersion.String(),
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
			Status: status{
				review.Status.Authenticated,
				userInfo{
					Username: review.Status.User.Username,
					UID:      review.Status.User.UID,
					Groups:   review.Status.User.Groups,
					Extra:    extra,
				},
				review.Status.Audiences,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(serveHTTP))
	server.TLS = tlsConfig
	server.StartTLS()

	// Adjust the path to point to our custom path
	serverURL, _ := url.Parse(server.URL)
	serverURL.Path = webhookPath
	server.URL = serverURL.String()

	return server, nil
}

// A service that can be set to say yes or no to authentication requests.
<<<<<<< HEAD
type mockV1beta1Service struct {
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
type mockV1Service struct {
=======
type mockV1beta1Service struct {
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	allow      bool
	statusCode int
	called     int
}

<<<<<<< HEAD
func (m *mockV1beta1Service) Review(r *authenticationv1beta1.TokenReview) {
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
func (m *mockV1Service) Review(r *authenticationv1.TokenReview) {
=======
func (m *mockV1beta1Service) Review(r *authenticationv1beta1.TokenReview) {
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	m.called++
	r.Status.Authenticated = m.allow
	if m.allow {
		r.Status.User.Username = "realHooman@email.com"
	}
}
<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
func (m *mockV1Service) Allow()              { m.allow = true }
func (m *mockV1Service) Deny()               { m.allow = false }
func (m *mockV1Service) HTTPStatusCode() int { return m.statusCode }

// newV1TokenAuthenticator creates a temporary kubeconfig file from the provided
// arguments and attempts to load a new WebhookTokenAuthenticator from it.
func newV1TokenAuthenticator(serverURL string, clientCert, clientKey, ca []byte, cacheTime time.Duration, implicitAuds authenticator.Audiences) (authenticator.Token, error) {
=======
>>>>>>> k8s/release-1.23
func (m *mockV1beta1Service) Allow()              { m.allow = true }
func (m *mockV1beta1Service) Deny()               { m.allow = false }
func (m *mockV1beta1Service) HTTPStatusCode() int { return m.statusCode }

// newV1beta1TokenAuthenticator creates a temporary kubeconfig file from the provided
// arguments and attempts to load a new WebhookTokenAuthenticator from it.
func newV1beta1TokenAuthenticator(serverURL string, clientCert, clientKey, ca []byte, cacheTime time.Duration, implicitAuds authenticator.Audiences) (authenticator.Token, error) {
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	tempfile, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	p := tempfile.Name()
	defer os.Remove(p)
	config := v1.Config{
		Clusters: []v1.NamedCluster{
			{
				Cluster: v1.Cluster{Server: serverURL, CertificateAuthorityData: ca},
			},
		},
		AuthInfos: []v1.NamedAuthInfo{
			{
				AuthInfo: v1.AuthInfo{ClientCertificateData: clientCert, ClientKeyData: clientKey},
			},
		},
	}
	if err := json.NewEncoder(tempfile).Encode(config); err != nil {
		return nil, err
	}

<<<<<<< HEAD
	c, err := tokenReviewInterfaceFromKubeconfig(p, "v1beta1")
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
	c, err := tokenReviewInterfaceFromKubeconfig(p, "v1")
=======
	c, err := tokenReviewInterfaceFromKubeconfig(p, "v1beta1", testRetryBackoff, nil)
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	if err != nil {
		return nil, err
	}

<<<<<<< HEAD
	authn, err := newWithBackoff(c, 0, implicitAuds)
=======
	authn, err := newWithBackoff(c, testRetryBackoff, implicitAuds, 10*time.Second, AuthenticatorMetrics{
		RecordRequestTotal:   noopMetrics{}.RequestTotal,
		RecordRequestLatency: noopMetrics{}.RequestLatency,
	})
>>>>>>> k8s/release-1.23
	if err != nil {
		return nil, err
	}

	return cache.New(authn, false, cacheTime, cacheTime), nil
}

<<<<<<< HEAD
func TestV1beta1TLSConfig(t *testing.T) {
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
func TestV1TLSConfig(t *testing.T) {
=======
func TestV1beta1TLSConfig(t *testing.T) {
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	tests := []struct {
		test                            string
		clientCert, clientKey, clientCA []byte
		serverCert, serverKey, serverCA []byte
		wantErr                         bool
	}{
		{
			test:       "TLS setup between client and server",
			clientCert: clientCert, clientKey: clientKey, clientCA: caCert,
			serverCert: serverCert, serverKey: serverKey, serverCA: caCert,
		},
		{
			test:       "Server does not require client auth",
			clientCA:   caCert,
			serverCert: serverCert, serverKey: serverKey,
		},
		{
			test:       "Server does not require client auth, client provides it",
			clientCert: clientCert, clientKey: clientKey, clientCA: caCert,
			serverCert: serverCert, serverKey: serverKey,
		},
		{
			test:       "Client does not trust server",
			clientCert: clientCert, clientKey: clientKey,
			serverCert: serverCert, serverKey: serverKey,
			wantErr: true,
		},
		{
			test:       "Server does not trust client",
			clientCert: clientCert, clientKey: clientKey, clientCA: caCert,
			serverCert: serverCert, serverKey: serverKey, serverCA: badCACert,
			wantErr: true,
		},
		{
			// Plugin does not support insecure configurations.
			test:    "Server is using insecure connection",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		// Use a closure so defer statements trigger between loop iterations.
		func() {
<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			service := new(mockV1Service)
			service.statusCode = 200

			server, err := NewV1TestServer(service, tt.serverCert, tt.serverKey, tt.serverCA)
=======
>>>>>>> k8s/release-1.23
			service := new(mockV1beta1Service)
			service.statusCode = 200

			server, err := NewV1beta1TestServer(service, tt.serverCert, tt.serverKey, tt.serverCA)
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
			if err != nil {
				t.Errorf("%s: failed to create server: %v", tt.test, err)
				return
			}
			defer server.Close()

<<<<<<< HEAD
			wh, err := newV1beta1TokenAuthenticator(server.URL, tt.clientCert, tt.clientKey, tt.clientCA, 0, nil)
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			wh, err := newV1TokenAuthenticator(server.URL, tt.clientCert, tt.clientKey, tt.clientCA, 0, nil)
=======
			wh, err := newV1beta1TokenAuthenticator(server.URL, tt.clientCert, tt.clientKey, tt.clientCA, 0, nil)
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
			if err != nil {
				t.Errorf("%s: failed to create client: %v", tt.test, err)
				return
			}

			// Allow all and see if we get an error.
			service.Allow()
			_, authenticated, err := wh.AuthenticateToken(context.Background(), "t0k3n")
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error making authorization request: %v", err)
				}
				return
			}
			if !authenticated {
				t.Errorf("%s: failed to authenticate token", tt.test)
				return
			}

			service.Deny()
			_, authenticated, err = wh.AuthenticateToken(context.Background(), "t0k3n")
			if err != nil {
				t.Errorf("%s: unexpectedly failed AuthenticateToken", tt.test)
			}
			if authenticated {
				t.Errorf("%s: incorrectly authenticated token", tt.test)
			}
		}()
	}
}

<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
// recorderV1Service records all token review requests, and responds with the
// provided TokenReviewStatus.
type recorderV1Service struct {
	lastRequest authenticationv1.TokenReview
	response    authenticationv1.TokenReviewStatus
}

func (rec *recorderV1Service) Review(r *authenticationv1.TokenReview) {
=======
>>>>>>> k8s/release-1.23
// recorderV1beta1Service records all token review requests, and responds with the
// provided TokenReviewStatus.
type recorderV1beta1Service struct {
	lastRequest authenticationv1beta1.TokenReview
	response    authenticationv1beta1.TokenReviewStatus
}

func (rec *recorderV1beta1Service) Review(r *authenticationv1beta1.TokenReview) {
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	rec.lastRequest = *r
	r.Status = rec.response
}

<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
func (rec *recorderV1Service) HTTPStatusCode() int { return 200 }

func TestV1WebhookTokenAuthenticator(t *testing.T) {
	serv := &recorderV1Service{}

	s, err := NewV1TestServer(serv, serverCert, serverKey, caCert)
=======
>>>>>>> k8s/release-1.23
func (rec *recorderV1beta1Service) HTTPStatusCode() int { return 200 }

func TestV1beta1WebhookTokenAuthenticator(t *testing.T) {
	serv := &recorderV1beta1Service{}

	s, err := NewV1beta1TestServer(serv, serverCert, serverKey, caCert)
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	expTypeMeta := metav1.TypeMeta{
<<<<<<< HEAD
		APIVersion: "authentication.k8s.io/v1beta1",
=======
		APIVersion: "authentication.k8s.io/v1",
>>>>>>> k8s/release-1.23
		Kind:       "TokenReview",
	}

	tests := []struct {
		description           string
		implicitAuds, reqAuds authenticator.Audiences
<<<<<<< HEAD
		serverResponse        authenticationv1beta1.TokenReviewStatus
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
		serverResponse        authenticationv1.TokenReviewStatus
=======
		serverResponse        authenticationv1beta1.TokenReviewStatus
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
		expectedAuthenticated bool
		expectedUser          *user.DefaultInfo
		expectedAuds          authenticator.Audiences
	}{
		{
			description: "successful response should pass through all user info.",
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
			},
			expectedAuthenticated: true,
			expectedUser: &user.DefaultInfo{
				Name: "somebody",
			},
		},
		{
			description: "successful response should pass through all user info.",
<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "person@place.com",
					UID:      "abcd-1234",
					Groups:   []string{"stuff-dev", "main-eng"},
					Extra:    map[string]authenticationv1.ExtraValue{"foo": {"bar", "baz"}},
=======
>>>>>>> k8s/release-1.23
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
					Username: "person@place.com",
					UID:      "abcd-1234",
					Groups:   []string{"stuff-dev", "main-eng"},
					Extra:    map[string]authenticationv1beta1.ExtraValue{"foo": {"bar", "baz"}},
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
				},
			},
			expectedAuthenticated: true,
			expectedUser: &user.DefaultInfo{
				Name:   "person@place.com",
				UID:    "abcd-1234",
				Groups: []string{"stuff-dev", "main-eng"},
				Extra:  map[string][]string{"foo": {"bar", "baz"}},
			},
		},
		{
			description: "unauthenticated shouldn't even include extra provided info.",
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: false,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: false,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "garbage",
					UID:      "abcd-1234",
					Groups:   []string{"not-actually-used"},
				},
			},
			expectedAuthenticated: false,
			expectedUser:          nil,
		},
		{
			description: "unauthenticated shouldn't even include extra provided info.",
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
				Authenticated: false,
			},
			expectedAuthenticated: false,
			expectedUser:          nil,
		},
		{
			description:  "good audience",
			implicitAuds: apiAuds,
			reqAuds:      apiAuds,
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
			},
			expectedAuthenticated: true,
			expectedUser: &user.DefaultInfo{
				Name: "somebody",
			},
			expectedAuds: apiAuds,
		},
		{
			description:  "good audience",
			implicitAuds: append(apiAuds, "other"),
			reqAuds:      apiAuds,
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
			},
			expectedAuthenticated: true,
			expectedUser: &user.DefaultInfo{
				Name: "somebody",
			},
			expectedAuds: apiAuds,
		},
		{
			description:  "bad audiences",
			implicitAuds: apiAuds,
			reqAuds:      authenticator.Audiences{"other"},
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
				Authenticated: false,
			},
			expectedAuthenticated: false,
		},
		{
			description:  "bad audiences",
			implicitAuds: apiAuds,
			reqAuds:      authenticator.Audiences{"other"},
			// webhook authenticator hasn't been upgraded to support audience.
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
			},
			expectedAuthenticated: false,
		},
		{
			description:  "audience aware backend",
			implicitAuds: apiAuds,
			reqAuds:      apiAuds,
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
				Audiences: []string(apiAuds),
			},
			expectedAuthenticated: true,
			expectedUser: &user.DefaultInfo{
				Name: "somebody",
			},
			expectedAuds: apiAuds,
		},
		{
			description: "audience aware backend",
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
				Audiences: []string(apiAuds),
			},
			expectedAuthenticated: true,
			expectedUser: &user.DefaultInfo{
				Name: "somebody",
			},
		},
		{
			description:  "audience aware backend",
			implicitAuds: apiAuds,
			reqAuds:      apiAuds,
<<<<<<< HEAD
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			serverResponse: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
=======
			serverResponse: authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
					Username: "somebody",
				},
				Audiences: []string{"other"},
			},
			expectedAuthenticated: false,
		},
	}
<<<<<<< HEAD
	token := "my-s3cr3t-t0ken"
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			wh, err := newV1beta1TokenAuthenticator(s.URL, clientCert, clientKey, caCert, 0, tt.implicitAuds)
=======
	token := "my-s3cr3t-t0ken" // Fake token for testing.
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
			wh, err := newV1TokenAuthenticator(s.URL, clientCert, clientKey, caCert, 0, tt.implicitAuds)
=======
			wh, err := newV1beta1TokenAuthenticator(s.URL, clientCert, clientKey, caCert, 0, tt.implicitAuds)
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if tt.reqAuds != nil {
				ctx = authenticator.WithAudiences(ctx, tt.reqAuds)
			}

			serv.response = tt.serverResponse
			resp, authenticated, err := wh.AuthenticateToken(ctx, token)
			if err != nil {
				t.Fatalf("authentication failed: %v", err)
			}
			if serv.lastRequest.Spec.Token != token {
				t.Errorf("Server did not see correct token. Got %q, expected %q.",
					serv.lastRequest.Spec.Token, token)
			}
			if !reflect.DeepEqual(serv.lastRequest.TypeMeta, expTypeMeta) {
				t.Errorf("Server did not see correct TypeMeta. Got %v, expected %v",
					serv.lastRequest.TypeMeta, expTypeMeta)
			}
			if authenticated != tt.expectedAuthenticated {
				t.Errorf("Plugin returned incorrect authentication response. Got %t, expected %t.",
					authenticated, tt.expectedAuthenticated)
			}
			if resp != nil && tt.expectedUser != nil && !reflect.DeepEqual(resp.User, tt.expectedUser) {
				t.Errorf("Plugin returned incorrect user. Got %#v, expected %#v",
					resp.User, tt.expectedUser)
			}
			if resp != nil && tt.expectedAuds != nil && !reflect.DeepEqual(resp.Audiences, tt.expectedAuds) {
				t.Errorf("Plugin returned incorrect audiences. Got %#v, expected %#v",
					resp.Audiences, tt.expectedAuds)
			}
		})
	}
}

<<<<<<< HEAD
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
type authenticationV1UserInfo authenticationv1.UserInfo

func (a *authenticationV1UserInfo) GetName() string     { return a.Username }
func (a *authenticationV1UserInfo) GetUID() string      { return a.UID }
func (a *authenticationV1UserInfo) GetGroups() []string { return a.Groups }

func (a *authenticationV1UserInfo) GetExtra() map[string][]string {
=======
>>>>>>> k8s/release-1.23
type authenticationV1beta1UserInfo authenticationv1beta1.UserInfo

func (a *authenticationV1beta1UserInfo) GetName() string     { return a.Username }
func (a *authenticationV1beta1UserInfo) GetUID() string      { return a.UID }
func (a *authenticationV1beta1UserInfo) GetGroups() []string { return a.Groups }

func (a *authenticationV1beta1UserInfo) GetExtra() map[string][]string {
<<<<<<< HEAD
=======
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	if a.Extra == nil {
		return nil
	}
	ret := map[string][]string{}
	for k, v := range a.Extra {
		ret[k] = []string(v)
	}

	return ret
}

<<<<<<< HEAD
// Ensure authenticationv1beta1.UserInfo contains the fields necessary to implement the
// user.Info interface.
var _ user.Info = (*authenticationV1beta1UserInfo)(nil)
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
// Ensure authenticationv1.UserInfo contains the fields necessary to implement the
// user.Info interface.
var _ user.Info = (*authenticationV1UserInfo)(nil)
=======
// Ensure authenticationv1beta1.UserInfo contains the fields necessary to implement the
// user.Info interface.
var _ user.Info = (*authenticationV1beta1UserInfo)(nil)
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23

// TestWebhookCache verifies that error responses from the server are not
// cached, but successful responses are. It also ensures that the webhook
// call is retried on 429 and 500+ errors
<<<<<<< HEAD
func TestV1beta1WebhookCacheAndRetry(t *testing.T) {
	serv := new(mockV1beta1Service)
	s, err := NewV1beta1TestServer(serv, serverCert, serverKey, caCert)
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
func TestV1WebhookCacheAndRetry(t *testing.T) {
	serv := new(mockV1Service)
	s, err := NewV1TestServer(serv, serverCert, serverKey, caCert)
=======
func TestV1beta1WebhookCacheAndRetry(t *testing.T) {
	serv := new(mockV1beta1Service)
	s, err := NewV1beta1TestServer(serv, serverCert, serverKey, caCert)
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create an authenticator that caches successful responses "forever" (100 days).
<<<<<<< HEAD
	wh, err := newV1beta1TokenAuthenticator(s.URL, clientCert, clientKey, caCert, 2400*time.Hour, nil)
=======
<<<<<<< HEAD:plugin/pkg/authenticator/token/webhook/webhook_v1_test.go
	wh, err := newV1TokenAuthenticator(s.URL, clientCert, clientKey, caCert, 2400*time.Hour, nil)
=======
	wh, err := newV1beta1TokenAuthenticator(s.URL, clientCert, clientKey, caCert, 2400*time.Hour, nil)
>>>>>>> k8s/release-1.23:plugin/pkg/authenticator/token/webhook/webhook_v1beta1_test.go
>>>>>>> k8s/release-1.23
	if err != nil {
		t.Fatal(err)
	}

	testcases := []struct {
		description string

		token string
		allow bool
		code  int

		expectError bool
		expectOk    bool
		expectCalls int
	}{
		{
			description: "t0k3n, 500 error, retries and fails",

			token: "t0k3n",
			allow: false,
			code:  500,

			expectError: true,
			expectOk:    false,
			expectCalls: 5,
		},
		{
			description: "t0k3n, 404 error, fails (but no retry)",

			token: "t0k3n",
			allow: false,
			code:  404,

			expectError: true,
			expectOk:    false,
			expectCalls: 1,
		},
		{
			description: "t0k3n, 200 response, allowed, succeeds with a single call",

			token: "t0k3n",
			allow: true,
			code:  200,

			expectError: false,
			expectOk:    true,
			expectCalls: 1,
		},
		{
			description: "t0k3n, 500 response, disallowed, but never called because previous 200 response was cached",

			token: "t0k3n",
			allow: false,
			code:  500,

			expectError: false,
			expectOk:    true,
			expectCalls: 0,
		},

		{
			description: "an0th3r_t0k3n, 500 response, disallowed, should be called again with retries",

			token: "an0th3r_t0k3n",
			allow: false,
			code:  500,

			expectError: true,
			expectOk:    false,
			expectCalls: 5,
		},
		{
			description: "an0th3r_t0k3n, 429 response, disallowed, should be called again with retries",

			token: "an0th3r_t0k3n",
			allow: false,
			code:  429,

			expectError: true,
			expectOk:    false,
			expectCalls: 5,
		},
		{
			description: "an0th3r_t0k3n, 200 response, allowed, succeeds with a single call",

			token: "an0th3r_t0k3n",
			allow: true,
			code:  200,

			expectError: false,
			expectOk:    true,
			expectCalls: 1,
		},
		{
			description: "an0th3r_t0k3n, 500 response, disallowed, but never called because previous 200 response was cached",

			token: "an0th3r_t0k3n",
			allow: false,
			code:  500,

			expectError: false,
			expectOk:    true,
			expectCalls: 0,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.description, func(t *testing.T) {
			serv.allow = testcase.allow
			serv.statusCode = testcase.code
			serv.called = 0

			_, ok, err := wh.AuthenticateToken(context.Background(), testcase.token)
			hasError := err != nil
			if hasError != testcase.expectError {
				t.Errorf("Webhook returned HTTP %d, expected error=%v, but got error %v", testcase.code, testcase.expectError, err)
			}
			if serv.called != testcase.expectCalls {
				t.Errorf("Expected %d calls, got %d", testcase.expectCalls, serv.called)
			}
			if ok != testcase.expectOk {
				t.Errorf("Expected ok=%v, got %v", testcase.expectOk, ok)
			}
		})
	}
}
