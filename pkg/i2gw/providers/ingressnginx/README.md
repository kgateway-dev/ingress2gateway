# Ingress Nginx Provider

The project supports translating ingress-nginx specific annotations.

## Ingress Class Name

To specify the name of the Ingress class to select, use `--ingress-nginx-ingress-class=ingress-nginx` (default to 'nginx').

## Supported Annotations

The ingress-nginx provider currently supports translating the following annotations to Gateway API and/or Kgateway-specific resources.

### Canary / Traffic Shaping

- `nginx.ingress.kubernetes.io/canary`: If set to `true`, enables weighted backends.

- `nginx.ingress.kubernetes.io/canary-by-header`: Specifies the header name used to generate an HTTPHeaderMatch.

- `nginx.ingress.kubernetes.io/canary-by-header-value`: Specifies the exact header value to match.

- `nginx.ingress.kubernetes.io/canary-by-header-pattern`: Specifies a regex pattern used in the header match.

- `nginx.ingress.kubernetes.io/canary-weight`: Specifies the backend weight for traffic shifting.

- `nginx.ingress.kubernetes.io/canary-weight-total`: Defines the total weight used when calculating backend percentages.

---

### Request / Body Size

- `nginx.ingress.kubernetes.io/client-body-buffer-size`: Sets the maximum request body size when `proxy-body-size` is not present. For the Kgateway implementation, this maps to `TrafficPolicy.spec.buffer.maxRequestSize`.

- `nginx.ingress.kubernetes.io/proxy-body-size`: Sets the maximum allowed request body size. Takes precedence over `client-body-buffer-size`. For the Kgateway implementation, this maps to `TrafficPolicy.spec.buffer.maxRequestSize`.

---

### CORS

- `nginx.ingress.kubernetes.io/enable-cors`: Enables CORS policy generation. When set to "true", enables CORS handling for the Ingress.
  Maps to creation of a TrafficPolicy with `spec.cors` populated.
- `nginx.ingress.kubernetes.io/cors-allow-origin`: Comma-separated list of origins (e.g. "https://example.com, https://another.com").
  For the Kgateway implementation, this maps to `TrafficPolicy.spec.cors.allowOrigins`.
- `nginx.ingress.kubernetes.io/cors-allow-credentials`: Controls whether credentials are allowed in cross-origin requests ("true" / "false").
  For the Kgateway implementation, this maps to `TrafficPolicy.spec.cors.allowCredentials`.
- `nginx.ingress.kubernetes.io/cors-allow-headers`: A comma-separated list of allowed request headers. For the Kgateway implementation,
  this maps to `TrafficPolicy.spec.cors.allowHeaders`.
- `nginx.ingress.kubernetes.io/cors-expose-headers`: A comma-separated list of HTTP response headers that can be exposed to client-side
  scripts in response to a cross-origin request. For the Kgateway implementation, this maps to `TrafficPolicy.spec.cors.exposeHeaders`.
- `nginx.ingress.kubernetes.io/cors-allow-methods`: A comma-separated list of allowed HTTP methods (e.g. "GET, POST, OPTIONS").
  For the Kgateway implementation, this maps to `TrafficPolicy.spec.cors.allowMethods`.
- `nginx.ingress.kubernetes.io/cors-max-age`: Controls how long preflight responses may be cached (in seconds). For the Kgateway
  implementation, this maps to `TrafficPolicy.spec.cors.maxAge`.

### Rate Limiting

- `nginx.ingress.kubernetes.io/limit-rps`: Requests per second limit.  For the Kgateway implementation, this maps to `TrafficPolicy.spec.rateLimit.local.tokenBucket`.

- `nginx.ingress.kubernetes.io/limit-rpm`: Requests per minute limit. For the Kgateway implementation, this maps to `TrafficPolicy.spec.rateLimit.local.tokenBucket`.

- `nginx.ingress.kubernetes.io/limit-burst-multiplier`: Burst multiplier for rate limiting. Used to compute `maxTokens`.

---

### Timeouts

- `nginx.ingress.kubernetes.io/proxy-send-timeout`: Controls the request timeout. For the Kgateway implementation, this maps to `TrafficPolicy.spec.timeouts.request`.

- `nginx.ingress.kubernetes.io/proxy-read-timeout`: Controls stream idle timeout. For the Kgateway implementation, this maps to `TrafficPolicy.spec.timeouts.streamIdle`.

---

### External Auth

- `nginx.ingress.kubernetes.io/auth-url`: Specifies the URL of an external authentication service. For the Kgateway implementation, this maps to `GatewayExtension.spec.extAuth.httpService`.
- `nginx.ingress.kubernetes.io/auth-response-headers`: Comma-separated list of headers to pass to backend once authentication request completes. For the Kgateway implementation, this maps to `GatewayExtension.spec.extAuth.httpService.authorizationResponse.headersToBackend`.

### Basic Auth

- `nginx.ingress.kubernetes.io/auth-type`: Must be set to `"basic"` to enable basic authentication. For the Kgateway implementation, this maps to `TrafficPolicy.spec.basicAuth`.
- `nginx.ingress.kubernetes.io/auth-secret`: Specifies the secret containing basic auth credentials in `namespace/name` format (or just `name` if in the same namespace). For the Kgateway implementation, this maps to `TrafficPolicy.spec.basicAuth.secretRef.name`.

---

### Backend (Upstream) Configuration

- `nginx.ingress.kubernetes.io/proxy-connect-timeout`: Controls the upstream connection timeout. For the Kgateway implementation,
  this maps to `BackendConfigPolicy.spec.connectTimeout`.
- `nginx.ingress.kubernetes.io/load-balance`: Sets the algorithm to use for load balancing. The only supported value is `round_robin`.
  For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer`.

**Note:** For the Kgateway implementation, if multiple Ingress resources reference the same Service with different `proxy-connect-timeout` values, ingress2gateway will emit warnings because Kgateway cannot safely apply multiple conflicting `BackendConfigPolicy` resources to the same Service.

---

### Backend TLS

- `nginx.ingress.kubernetes.io/proxy-ssl-secret`: Specifies a Secret containing client certificate (`tls.crt`), client key (`tls.key`), and optionally CA certificate (`ca.crt`) in PEM format. The secret name can be specified as `secretName` (same namespace) or `namespace/secretName`. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.tls.secretRef`. **Note:** The secret must be in the same namespace as the BackendConfigPolicy.

- `nginx.ingress.kubernetes.io/proxy-ssl-verify`: Enables or disables verification of the proxied HTTPS server certificate. Values: `"on"` or `"off"` (default: `"off"`). For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.tls.insecureSkipVerify` (inverted: `"on"` = `false`, `"off"` = `true`).

- `nginx.ingress.kubernetes.io/proxy-ssl-name`: Overrides the server name used to verify the certificate of the proxied HTTPS server. This value is also passed through SNI (Server Name Indication) when establishing a connection. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.tls.sni`. Setting this value automatically enables SNI.

- `nginx.ingress.kubernetes.io/proxy-ssl-server-name`: **Note:** This annotation is not handled separately. In Kgateway, SNI is automatically enabled when `proxy-ssl-name` is set.

**Note:** For the Kgateway implementation, backend TLS configuration is applied via `BackendConfigPolicy` resources. If multiple Ingress resources reference the same Service with different backend TLS settings, ingress2gateway will create a single `BackendConfigPolicy` per Service, and conflicting settings may result in warnings.

---

### Session Affinity

- `nginx.ingress.kubernetes.io/affinity`: Enables and sets the affinity type in all Upstreams of an Ingress. The only affinity type available for NGINX is "cookie". For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies` with cookie-based hash policy.

- `nginx.ingress.kubernetes.io/session-cookie-name`: Defines the name of the cookie used for session affinity. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.name`.

- `nginx.ingress.kubernetes.io/session-cookie-path`: Defines the path that will be set on the cookie. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.path`.

- `nginx.ingress.kubernetes.io/session-cookie-domain`: Sets the Domain attribute of the sticky cookie. **Note:** This annotation is parsed but not currently mapped to kgateway as the Cookie type doesn't support domain.

- `nginx.ingress.kubernetes.io/session-cookie-samesite`: Applies a SameSite attribute to the sticky cookie. Browser accepted values are None, Lax, and Strict. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.sameSite`.

- `nginx.ingress.kubernetes.io/session-cookie-expires`: Sets the TTL/expiration time for the cookie. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.ttl`.

- `nginx.ingress.kubernetes.io/session-cookie-max-age`: Sets the TTL/expiration time for the cookie. Takes precedence over `session-cookie-expires` if both are specified. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.ttl`.

- `nginx.ingress.kubernetes.io/session-cookie-secure`: Sets the Secure flag on the cookie. For the Kgateway implementation, this maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.secure`.

---

### SSL Redirect

- `nginx.ingress.kubernetes.io/ssl-redirect`: When set to `"true"`, enables SSL redirect for HTTP requests. For the Kgateway implementation, this maps to a `RequestRedirect` filter on HTTPRoute rules that redirects HTTP to HTTPS with a 301 status code.

- `nginx.ingress.kubernetes.io/force-ssl-redirect`: When set to `"true"`, enables SSL redirect for HTTP requests. This annotation is treated exactly the same as `ssl-redirect`. For the Kgateway implementation, this maps to a `RequestRedirect` filter on HTTPRoute rules that redirects HTTP to HTTPS with a 301 status code.

**Note:** Both annotations are supported and treated identically. If either annotation is set to `"true"` (case-insensitive), SSL redirect will be enabled. The redirect filter is added at the rule level in the HTTPRoute, redirecting all HTTP traffic to HTTPS.

---

## Provider Limitations

- Currently, kgateway is the only supported implementation-specific emitter.
- Some NGINX behaviors cannot be reproduced exactly due to differences between NGINX and semantics of other proxy implementations.

If you rely on annotations not listed above, please open an issue or be prepared to apply post-migration manual adjustments.
