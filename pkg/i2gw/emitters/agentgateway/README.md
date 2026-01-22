# Agentgateway Emitter

The Agentgateway Emitter supports generating **Gateway API** resources plus **agentgateway**-specific extensions
from Ingress manifests using:

- **Provider**: `ingress-nginx`

**Note:** All other providers will be ignored by the emitter.

## What it outputs

- Standard **Gateway API** objects (Gateways, HTTPRoutes, etc.)
- Agentgateway extension objects emitted as unstructured resources, e.g. `AgentgatewayPolicy`.

The emitter also ensures that any generated Gateway resources use:

- `spec.gatewayClassName: agentgateway`

## Development Workflow

The typical development workflow for adding an Ingress NGINX feature to the Agentgateway emitter is:

1. Use [this issue](https://github.com/kubernetes-sigs/ingress2gateway/issues/232) to prioritize the list of Ingress NGINX features unless
   the business provides requirements. When this list is complete, refer to [this doc](https://docs.google.com/document/d/12ejNTb45hASGYvUjd3t9mfNwuMTX3KBM68ALM4jRFBY/edit?usp=sharing) for additional features. **Note:** Several of the features from the above list have already been implemented, so review the
   current supported features before adding more.
2. If a feature cannot map to an existing agentgateway API, open an Agentgateway issue describing what’s needed.
3. Extend the ingress-nginx IR/generic Policy IR as needed so the provider can represent the feature in a structured way.
4. Add a feature-specific function to the ingress-nginx provider (`pkg/i2gw/providers/ingressnginx`), e.g.
   `rateLimitFeature()`, that parses the Ingress NGINX annotation(s) and records them as generic Policies in the
   provider IR.
5. Update the Agentgateway Emitter (`pkg/i2gw/emitters/agentgateway/emitter.go`) to consume the IR and emit
   agentgateway-specific resources.
6. Add/extend integration and e2e tests to cover the new behavior.
7. Update the list of supported annotations with the feature you added.
8. Submit a PR to merge your changes upstream. [This branch](https://github.com/danehans/ingress2gateway/tree/impl_emitter_nginx_feat) is the **current** upstream, but [k8s-sigs](https://github.com/kubernetes-sigs/ingress2gateway) or [solo](https://github.com/solo-io/ingress2gateway) repos should be used before releasing.

## Testing

Run the tool with a test input manifest:

```bash
go run . print \
  --providers=ingress-nginx \
  --emitter=agentgateway \
  --input-file ./pkg/i2gw/emitters/agentgateway/testing/testdata/<FEATURE>.yaml
```

The command should generate Gateway API resources plus agentgateway extension resources (when applicable).

## Notifications

Some conversions require follow-up user action that cannot be expressed safely as emitted manifests. In those cases,
the agentgateway emitter emits **INFO** notifications on the CLI during conversion.

Currently, the agentgateway emitter emits a notification when projecting **Basic Authentication**, because:

- ingress-nginx (auth-file) commonly expects htpasswd content under the Secret key **`auth`**
- agentgateway expects htpasswd content under the Secret key **`.htaccess`**

## Supported Annotations

### Traffic Behavior

#### CORS

The agentgateway emitter supports projecting CORS behavior based on the following Ingress NGINX annotations:

- `nginx.ingress.kubernetes.io/enable-cors`
- `nginx.ingress.kubernetes.io/cors-allow-origin`
- `nginx.ingress.kubernetes.io/cors-allow-methods`
- `nginx.ingress.kubernetes.io/cors-allow-headers`
- `nginx.ingress.kubernetes.io/cors-expose-headers`
- `nginx.ingress.kubernetes.io/cors-allow-credentials`
- `nginx.ingress.kubernetes.io/cors-max-age`

These are mapped into an `AgentgatewayPolicy` using agentgateway’s `Traffic.Cors` model (which inlines the Gateway API `HTTPCORSFilter`):

- `enable-cors`  `cors-allow-origin` → `AgentgatewayPolicy.spec.traffic.cors.allowOrigins`
- `cors-allow-headers` → `AgentgatewayPolicy.spec.traffic.cors.allowHeaders`
- `cors-expose-headers` → `AgentgatewayPolicy.spec.traffic.cors.exposeHeaders`
- `cors-allow-methods` → `AgentgatewayPolicy.spec.traffic.cors.allowMethods`
- `cors-allow-credentials` → `AgentgatewayPolicy.spec.traffic.cors.allowCredentials`
- `cors-max-age` → `AgentgatewayPolicy.spec.traffic.cors.maxAge`

**Notes:**

- The emitter only projects CORS when `enable-cors` is truthy **and** at least one value is present in `cors-allow-origin`.
- `cors-allow-origin` values are de-duped while preserving order; empty values are ignored.
- Header lists (`cors-allow-headers`, `cors-expose-headers`) are de-duped case-insensitively.
- Method values are normalized to upper-case and filtered to valid Gateway API HTTP methods (plus `*`); unknown values are ignored.
- If `cors-max-age` is unset or non-positive, it is not projected.

#### Basic Authentication

The agentgateway emitter supports projecting Basic Authentication from the following Ingress NGINX annotations:

- `nginx.ingress.kubernetes.io/auth-type` (supported: `basic`)
- `nginx.ingress.kubernetes.io/auth-secret`
- `nginx.ingress.kubernetes.io/auth-secret-type` (supported: `auth-file`)

These are mapped into an `AgentgatewayPolicy` using agentgateway’s `Traffic.BasicAuthentication` model:

- `auth-secret` → `AgentgatewayPolicy.spec.traffic.basicAuthentication.secretRef.name`

**Notes:**

- The agentgateway API supports Basic Auth in two forms: inline `users` or a `secretRef`. The emitter currently
  projects only the `secretRef` form.
- `auth-secret-type` is accepted for parity with ingress-nginx. The emitter currently supports only the default
  ingress-nginx secret format: `auth-file`.
- Agentgateway expects the referenced Secret to contain a key named **`.htaccess`** with htpasswd-formatted content.
  (See the AgentgatewayPolicy API docs for details.)
- Ingress NGINX (auth-file format) typically expects htpasswd content under the key **`auth`** in the Secret.
  To support *both* dataplanes using the *same* Secret name, create a “dual-key” Secret containing **both**
  keys with the same htpasswd content:

  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: basic-auth
    namespace: default
  type: Opaque
  stringData:
    auth: |
      user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
    .htaccess: |
      user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
  ```

  This allows the same `nginx.ingress.kubernetes.io/auth-secret: basic-auth` reference to work for both
  ingress-nginx and agentgateway outputs.

#### Request Timeouts

The agentgateway emitter currently supports projecting request timeouts based on the following Ingress NGINX annotations:

- `nginx.ingress.kubernetes.io/proxy-send-timeout`
- `nginx.ingress.kubernetes.io/proxy-read-timeout`

These are mapped into an `AgentgatewayPolicy` using agentgateway’s `Traffic.Timeouts` model:

- `proxy-send-timeout` → `AgentgatewayPolicy.spec.traffic.timeouts.request`
- `proxy-read-timeout` → `AgentgatewayPolicy.spec.traffic.timeouts.request`

**Notes:**

- If **both** annotations are set, the emitter uses the **larger** of the two values for
  `spec.traffic.timeouts.request` to avoid unexpectedly truncating requests.
- Invalid/unsupported duration values are ignored by the provider and will not be projected.

#### Local Rate Limiting

The agentgateway emitter currently supports projecting local rate limiting via:

- `nginx.ingress.kubernetes.io/limit-rps`
- `nginx.ingress.kubernetes.io/limit-rpm`
- `nginx.ingress.kubernetes.io/limit-burst-multiplier`

These are mapped into an `AgentgatewayPolicy` using agentgateway’s `LocalRateLimit` model:

- `limit-rps` → `LocalRateLimit{ requests: <limit>, unit: Seconds }`
- `limit-rpm` → `LocalRateLimit{ requests: <limit>, unit: Minutes }`
- `limit-burst-multiplier` (when > 1) → `LocalRateLimit{ burst: limit * multiplier }`

**Notes:**

- Burst multiplier defaults to `1` if unset/zero.
- Unknown/unsupported units are ignored.

## AgentgatewayPolicy Projection

Rate limit, timeout, CORS, and basic auth annotations are converted into `AgentgatewayPolicy` resources.

### Naming

Policies are created **per source Ingress name**:

- `metadata.name: <ingress-name>`
- `metadata.namespace: <route-namespace>`

### Attachment Semantics

If a policy covers all backends of the generated HTTPRoute, the policy is attached using `spec.targetRefs`
to the HTTPRoute.

If a policy only covers some (rule, backendRef) pairs, the emitter **returns an error** and does not emit
+agentgateway resources for that Ingress.

Conceptually:

- **Full coverage** → `AgentgatewayPolicy.spec.targetRefs[]` references the HTTPRoute
- **Partial coverage** → **error** (agentgateway does not support attaching `AgentgatewayPolicy` via per-backend
  `HTTPRoute` `ExtensionRef` filters)

#### Why?

Agentgateway does not support `HTTPRoute` `backendRefs[].filters[].type: ExtensionRef` for attaching policies.
Attempting to generate per-backend `ExtensionRef` filters results in `HTTPRoute` status failures (e.g.
`ResolvedRefs=False` with an `IncompatibleFilters` error). To avoid emitting manifests that will be rejected or
non-functional at runtime, the emitter fails fast during generation when only partial attachment is possible.

#### Workarounds

- Split the source Ingress into separate Ingress resources so each generated HTTPRoute can be fully covered by a policy.
- Adjust annotations so the policy applies uniformly to all paths/backends of the resulting HTTPRoute.

## Deterministic Output

For stable golden tests, agentgateway extension objects are sorted (Kind, Namespace, Name) before being appended
to the output extensions list.

## Limitations

- Only the **ingress-nginx provider** is currently supported by the Agentgateway emitter.
- Regex path matching is not currently implemented for agentgateway output.

## Future Work

The code defines GVKs for additional agentgateway extension types (e.g. `AgentgatewayBackend`), but they are not
yet emitted by the current implementation.
