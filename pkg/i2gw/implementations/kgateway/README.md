# Kgateway Emitter

The Kgateway Emitter supports generating **Gateway API** and **Kgateway** resources from Ingress manifests using:

- **Provider**: `ingress-nginx`

**Note:** All other providers will be ignored by the emitter.

## Development Workflow

The typical development workflow for adding an Ingress NGINX feature to the Kgateway emitter is:

1. Use [this issue](https://github.com/kubernetes-sigs/ingress2gateway/issues/232) to prioritize the list of Ingress NGINX features unless
   the business provides requirements. When this list is complete, refer to [this doc](https://docs.google.com/document/d/12ejNTb45hASGYvUjd3t9mfNwuMTX3KBM68ALM4jRFBY/edit?usp=sharing) for additional features. **Note:** Several of the festures from the above list have already been implemented, so review the
   current supported features before adding more.
2. If any of the above features cannot map to an existing Kgateway API, create a Kgateway issue, label it with `kind/ingress-nginx`,
   `help wanted`, `priority/high`, etc. and describe what's needed.
3. Extend the ingress-nginx IR (`pkg/i2gw/intermediate/provider_ingressnginx.go`) as needed. Most changes should fall within the Policy IR.
4. Add a feature-specific function to the ingress-nginx provider (`pkg/i2gw/providers/ingressnginx`), e.g. `proxyReadTimeoutFeature()`
   that parses the Ingress NGINX annotation from source Ingresses and records them as generic Policies in the ingress-nginx provider-specific IR.
5. Update the Kgateway Emitter (`pkg/i2gw/implementations/kgateway/emitter.go`) to consume the IR and return Kgateway-specific resources.
6. Follow the **Testing** section to test your changes.
7. Update the list of supported annotations with the feature you added.
8. Submit a PR to merge your changes upstream. [This branch](https://github.com/danehans/ingress2gateway/tree/impl_emitter_nginx_feat) is the **current** upstream, but [k8s-sigs](https://github.com/kubernetes-sigs/ingress2gateway) or [solo](https://github.com/solo-io/ingress2gateway) repos should be used before releasing.

## Testing

Run the tool with the test input manifest:

```bash
go run . print \
  --providers=ingress-nginx \
  --implementations=kgateway \
  --input-file ./pkg/i2gw/implementations/kgateway/testing/testdata/input.yaml
```

The command should generate Gateway API and Kgateway resources.

## Supported Annotations

### Implementation Selection

- `ingress2gateway.kubernetes.io/implementation: kgateway`: Tells the ingress-nginx provider to target the Kgateway implementation.
  This overrides the default GatewayClass name used by the provider.

### Traffic Behavior

- `nginx.ingress.kubernetes.io/client-body-buffer-size`
- `nginx.ingress.kubernetes.io/proxy-body-size`
- `nginx.ingress.kubernetes.io/enable-cors`
- `nginx.ingress.kubernetes.io/cors-allow-origin`
- `nginx.ingress.kubernetes.io/cors-allow-credentials`
- `nginx.ingress.kubernetes.io/cors-allow-headers`
- `nginx.ingress.kubernetes.io/cors-expose-headers`
- `nginx.ingress.kubernetes.io/cors-allow-methods`
- `nginx.ingress.kubernetes.io/cors-max-age`
- `nginx.ingress.kubernetes.io/limit-rps`
- `nginx.ingress.kubernetes.io/limit-rpm`
- `nginx.ingress.kubernetes.io/limit-burst-multiplier`
- `nginx.ingress.kubernetes.io/proxy-send-timeout`
- `nginx.ingress.kubernetes.io/proxy-read-timeout`
- `nginx.ingress.kubernetes.io/ssl-redirect`: When set to `"true"`, adds a `RequestRedirect` filter to HTTPRoute rules that redirects HTTP to HTTPS with a 301 status code.
- `nginx.ingress.kubernetes.io/force-ssl-redirect`: When set to `"true"`, adds a `RequestRedirect` filter to HTTPRoute rules that redirects HTTP to HTTPS with a 301 status code. Treated identically to `ssl-redirect`.

### Backend Behavior

- `nginx.ingress.kubernetes.io/proxy-connect-timeout`: Sets the timeout for establishing a connection with a proxied server. It should be noted that this timeout
  cannot usually exceed 75 seconds.
- `nginx.ingress.kubernetes.io/load-balance`: Sets the algorithm to use for load balancing to a proxied server. The only supported value is `round_robin`.
- `nginx.ingress.kubernetes.io/affinity`: Enables session affinity (only "cookie" type is supported). Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies`.
- `nginx.ingress.kubernetes.io/session-cookie-name`: Specifies the name of the cookie used for session affinity. Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.name`.
- `nginx.ingress.kubernetes.io/session-cookie-path`: Defines the path that will be set on the cookie. Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.path`.
- `nginx.ingress.kubernetes.io/session-cookie-domain`: Sets the Domain attribute of the sticky cookie. **Note:** This annotation is parsed but not currently mapped to kgateway as the Cookie type doesn't support domain.
- `nginx.ingress.kubernetes.io/session-cookie-samesite`: Applies a SameSite attribute to the sticky cookie. Browser accepted values are None, Lax, and Strict. Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.sameSite`.
- `nginx.ingress.kubernetes.io/session-cookie-expires`: Sets the TTL/expiration time for the cookie. Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.ttl`.
- `nginx.ingress.kubernetes.io/session-cookie-max-age`: Sets the TTL/expiration time for the cookie (takes precedence over `session-cookie-expires`). Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.ttl`.
- `nginx.ingress.kubernetes.io/session-cookie-secure`: Sets the Secure flag on the cookie. Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies[].cookie.secure`.
- `nginx.ingress.kubernetes.io/service-upstream`: When set to `"true"`, configures Kgateway to route to the Service’s cluster IP (or equivalent static host) instead of individual Pod IPs. For each covered Service, the emitter creates a `Backend` resource with `spec.type: Static` and rewrites the corresponding `HTTPRoute.spec.rules[].backendRefs[]` to reference that `Backend` (group `gateway.kgateway.dev`, kind `Backend`).

### External Auth

- `nginx.ingress.kubernetes.io/auth-url`: Specifies the URL of an external authentication service.
- `nginx.ingress.kubernetes.io/auth-response-headers`: Comma-separated list of headers to pass to backend once authentication request completes.

### Basic Auth

- `nginx.ingress.kubernetes.io/auth-type`: Must be set to `"basic"` to enable basic authentication. Maps to `TrafficPolicy.spec.basicAuth`.
- `nginx.ingress.kubernetes.io/auth-secret`: Specifies the secret containing basic auth credentials in `namespace/name` format (or just `name` if in the same namespace). Maps to `TrafficPolicy.spec.basicAuth.secretRef.name`.

### Backend TLS

- `nginx.ingress.kubernetes.io/proxy-ssl-secret`: Maps to `BackendConfigPolicy.spec.tls.secretRef`
- `nginx.ingress.kubernetes.io/proxy-ssl-verify`: Maps to `BackendConfigPolicy.spec.tls.insecureSkipVerify` (inverted: `"on"` = `false`, `"off"` = `true`)
- `nginx.ingress.kubernetes.io/proxy-ssl-name`: Maps to `BackendConfigPolicy.spec.tls.sni` (automatically enables SNI)

### Access Logging

- `nginx.ingress.kubernetes.io/enable-access-log`: If enabled, will create an HTTPListenerPolicy that will configure a basic policy for envoy access logging. Maps to `HTTPListenerPolicy.spec.accessLog[].fileSink`. This can be further customized as needed, see [docs](https://kgateway.dev/docs/envoy/2.0.x/security/access-logging/).

## TrafficPolicy Projection

Annotations in the **Traffic Behavior** category are converted into
`TrafficPolicy` resources.

These policies are attached using:

- `targetRefs` when the policy applies to all backends, or
- `extensionRef` backend filters for partial coverage.

Examples:

- Body size annotations control `spec.buffer.maxRequestSize`
- Rate limit annotations control `spec.rateLimit.local.tokenBucket`
- Timeout annotations control `spec.timeouts.request` or `streamIdle`
- SSL redirect annotations add `RequestRedirect` filters to HTTPRoute rules

## BackendConfigPolicy Projection

Annotations in the **Backend Behavior** category are converted into
`BackendConfigPolicy` resources.

Currently supported:

- `proxy-connect-timeout`: Maps to `BackendConfigPolicy.spec.connectTimeout`
- Session affinity annotations: Maps to `BackendConfigPolicy.spec.loadBalancer.ringHash.hashPolicies` with cookie-based hash policy

If multiple Ingresses target the same Service with conflicting `proxy-connect-timeout` values,
the lowest timeout wins and a warning is emitted.

## Backend Projection

Annotations that change how upstreams are represented (rather than how they are load balanced or configured)
can be projected into Kgateway `Backend` resources.

Currently supported:

- `nginx.ingress.kubernetes.io/service-upstream`:
  - For each Service backend covered by an Ingress with `service-upstream: "true"`, the emitter creates a `Backend` with:
    - `spec.type: Static`
    - `spec.static.hosts` containing a single `{host, port}` entry derived from the Service (e.g. `myservice.default.svc.cluster.local:80`).
  - Matching `HTTPRoute.spec.rules[].backendRefs[]` are rewritten to reference this `Backend` instead of the core Service.

### Summary of Policy Types

| Annotation Type                    | Kgateway Resource     |
|------------------------------------|-----------------------|
| Request/response behavior          | `TrafficPolicy`       |
| Upstream connection behavior       | `BackendConfigPolicy` |
| Upstream representation (static IP)| `Backend`             |

## Limitations

- Only the **ingress-nginx provider** is currently supported by the Kgateway emitter.
- Some NGINX behaviors cannot be reproduced exactly due to Envoy/Kgateway differences.

## Supported but not tranlated Annotations

The following annotations have equivalents in kgateway but are not (as of yet) translated by this tool.

`nginx.ingress.kubernetes.io/auth-proxy-set-headers`

Supported in TrafficPolicy

```yaml
spec:
  extAuth:
    httpService:
      authorizationRequest:
        headersToAdd:
        - key: x-forwarded-host
          value: "%DOWNSTREAM_REMOTE_ADDRESS%"
```
