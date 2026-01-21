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

## Supported Annotations

### Traffic Behavior

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

Rate limit annotations are converted into `AgentgatewayPolicy` resources.

### Naming

Policies are created **per source Ingress name**:

- `metadata.name: <ingress-name>`
- `metadata.namespace: <route-namespace>`

### Attachment Semantics

If a policy covers all backends of the generated HTTPRoute, the policy is attached using `spec.targetRefs`
to the HTTPRoute.

If a policy only covers some (rule, backendRef) pairs, the emitter attaches the policy using **per-backend**
`ExtensionRef` filters on the covered `backendRefs`.

Conceptually:

- **Full coverage** → `AgentgatewayPolicy.spec.targetRefs[]` references the HTTPRoute
- **Partial coverage** → `HTTPRoute.rules[].backendRefs[].filters[]` contains `type: ExtensionRef` pointing at the policy

## Deterministic Output

For stable golden tests, agentgateway extension objects are sorted (Kind, Namespace, Name) before being appended
to the output extensions list.

## Limitations

- Only the **ingress-nginx provider** is currently supported by the Agentgateway emitter.
- Regex path matching is not currently implemented for agentgateway output.

## Future Work

The code defines GVKs for additional agentgateway extension types (e.g. `AgentgatewayBackend`), but they are not
yet emitted by the current implementation.
