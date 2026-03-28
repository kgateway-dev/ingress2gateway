# Plan: Minimal Kgateway Emitter PR

## Overview
This plan outlines the steps to create a minimal kgateway emitter implementation for ingress2gateway with:
- Basic emitter scaffolding
- Support for CORS annotations: `nginx.ingress.kubernetes.io/enable-cors` and `nginx.ingress.kubernetes.io/cors-allow-origin`

## Architecture Context

The ingress2gateway tool follows this flow:
1. **Provider** (e.g., `ingress-nginx`) reads Ingress resources and annotations, converts them to an Intermediate Representation (IR)
2. **Common Emitter** processes the IR and generates standard Gateway API resources
3. **Implementation-specific Emitter** (e.g., `kgateway`) reads the IR and generates implementation-specific extensions

For this PR, we'll create a minimal kgateway emitter that:
- Converts standard Gateway API resources from IR
- Sets GatewayClassName to "kgateway"
- Supports CORS annotations: `enable-cors` + `cors-allow-origin` → creates `TrafficPolicy` with CORS configuration

## Files to Create/Modify

### 1. Core Emitter Files

#### `pkg/i2gw/emitters/kgateway/emitter.go`
- **Purpose**: Main emitter implementation
- **Key Components**:
  - `init()`: Register emitter with name "kgateway"
  - `NewEmitter()`: Constructor function
  - `Emit()`: Main conversion logic
    - Convert IR to Gateway API resources using `utils.ToGatewayResources()`
    - Set `GatewayClassName = "kgateway"` for all Gateways
    - Iterate through HTTPRoutes and apply CORS policy
    - Attach TrafficPolicy to HTTPRoute (via targetRefs or ExtensionRef filters)
    - Collect kgateway-specific resources and add to `GatewayExtensions`
    - Return `GatewayResources` and any errors

#### `pkg/i2gw/emitters/kgateway/types.go`
- **Purpose**: Define GroupVersionKind constants for kgateway resources
- **Key Components**:
  - `TrafficPolicyGVK`: GVK for TrafficPolicy resource
  - Constants for kgateway API group/version

#### `pkg/i2gw/emitters/kgateway/utils.go`
- **Purpose**: Helper utility functions
- **Key Components**:
  - `toUnstructured()`: Convert runtime.Object to unstructured.Unstructured
  - `ensureTrafficPolicy()`: Helper to create/get TrafficPolicy for an Ingress
  - `uniquePolicyIndices()`: Deduplicate policy indices
  - `numRules()`: Count total backend refs in HTTPRoute

#### `pkg/i2gw/emitters/kgateway/cors.go`
- **Purpose**: Handle CORS annotations
- **Key Components**:
  - `applyCorsPolicy()`: 
    - Check if `pol.Cors.Enable` is true and `pol.Cors.AllowOrigin` has values
    - Process AllowOrigin (dedupe, trim whitespace)
    - Process optional fields: AllowHeaders, ExposeHeaders, AllowMethods, AllowCredentials, MaxAge
    - Create/update TrafficPolicy with CORS configuration
    - Return true if policy was created/modified

### 2. Integration Files

#### `cmd/print.go`
- **Modification**: Add import for kgateway emitter package
  ```go
  _ "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitters/kgateway"
  ```
- **Purpose**: Ensure emitter is registered at startup

### 3. Documentation

#### `pkg/i2gw/emitters/kgateway/README.md`
- **Purpose**: Document the minimal implementation
- **Content**:
  - Brief description of the emitter
  - Supported provider: `ingress-nginx`
  - Supported annotations: 
    - `nginx.ingress.kubernetes.io/enable-cors` (required)
    - `nginx.ingress.kubernetes.io/cors-allow-origin` (optional, defaults to "*")
  - Example usage
  - Link to kgateway documentation

### 4. Test Data (Optional for initial PR)

#### `pkg/i2gw/emitters/kgateway/testing/testdata/input/cors.yaml`
- **Purpose**: Sample Ingress with CORS annotations

#### `pkg/i2gw/emitters/kgateway/testing/testdata/output/cors.yaml`
- **Purpose**: Expected output (Gateway, HTTPRoute, TrafficPolicy with CORS)

## Implementation Details

### CORS Policy Implementation

The CORS annotations map to `TrafficPolicy` with CORS configuration:

**Supported Annotations:**
- `nginx.ingress.kubernetes.io/enable-cors`: Must be `"true"` to enable CORS
- `nginx.ingress.kubernetes.io/cors-allow-origin`: Comma-separated list of allowed origins (defaults to `"*"` if not set)

**Optional Annotations (can be added later):**
- `nginx.ingress.kubernetes.io/cors-allow-credentials`
- `nginx.ingress.kubernetes.io/cors-allow-headers`
- `nginx.ingress.kubernetes.io/cors-expose-headers`
- `nginx.ingress.kubernetes.io/cors-allow-methods`
- `nginx.ingress.kubernetes.io/cors-max-age`

**Generated Resource:**
```yaml
apiVersion: gateway.kgateway.dev/v1alpha1
kind: TrafficPolicy
metadata:
  name: <ingress-name>
  namespace: <ingress-namespace>
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: <httproute-name>
  cors:
    httpCORSFilter:
      allowOrigins:
      - "*"  # or specific origins
      # Optional fields can be added here
```

### Key Implementation Points

1. **Policy Coverage**: 
   - If CORS applies to all backends in HTTPRoute → use `targetRefs` to attach to HTTPRoute
   - If CORS applies to specific backends → use `ExtensionRef` filters on those backendRefs
   
2. **TrafficPolicy Creation**: One TrafficPolicy per source Ingress name (tracked by `map[string]*kgateway.TrafficPolicy`)

3. **Data Processing**:
   - AllowOrigin: Dedupe while preserving order, trim whitespace
   - AllowHeaders/ExposeHeaders: Dedupe case-insensitively, convert to `gatewayv1.HTTPHeaderName`
   - AllowMethods: Normalize to uppercase, validate against Gateway API enum, dedupe
   - MaxAge: Only set if > 0

4. **Resource Collection**: Add TrafficPolicy to `kgatewayObjs` slice, convert to unstructured, add to `GatewayResources.GatewayExtensions`

## Dependencies

The emitter requires:
- `github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway` - kgateway API types
- `sigs.k8s.io/gateway-api/apis/v1` - Gateway API types
- `k8s.io/apimachinery` - Kubernetes API machinery

These should already be in `go.mod` if the full emitter exists, or need to be added.

## Testing Strategy

1. **Build and Run Tests**:
   ```bash
   # Run all checks (fmt, vet, verify, build, test-all)
   make all
   
   # Or run individually:
   make fmt      # Format code
   make vet      # Static analysis
   make test     # Integration tests
   make build    # Build binary
   ```

2. **Manual Testing with Sample Ingress**:
   ```bash
   # Build the binary first
   make build
   
   # Test with a sample Ingress manifest
   ./ingress2gateway print \
     --providers=ingress-nginx \
     --emitter=kgateway \
     --input-file <test-input.yaml>
   ```

3. **Verify Output**:
   - Gateway has `gatewayClassName: kgateway`
   - TrafficPolicy is created when CORS annotation is present
   - TrafficPolicy has correct CORS configuration with `allowOrigins`
   - TrafficPolicy is attached to HTTPRoute (via `targetRefs` or `ExtensionRef` filters)

## PR Checklist

### Repository Setup
- [ ] Fork the repository at https://github.com/kubernetes-sigs/ingress2gateway
- [ ] Clone your fork and add upstream remote
- [ ] Sync with upstream main branch
- [ ] Create feature branch: `feat/kgateway-emitter-minimal`

### Implementation
- [ ] Create `emitter.go` with minimal implementation
- [ ] Create `types.go` with GVK definitions
- [ ] Create `utils.go` with helper functions
- [ ] Create `cors.go` with CORS policy logic
- [ ] Update `cmd/print.go` to import emitter
- [ ] Create `README.md` with documentation
- [ ] (Optional) Add test data files

### Testing and Validation
- [ ] Verify code compiles (`make build` or `go build ./...`)
- [ ] Run code formatting (`make fmt`)
- [ ] Run static analysis (`make vet`)
- [ ] Run integration tests (`make test`)
- [ ] (Optional) Run e2e tests (`make test-e2e`)
- [ ] Run full verification (`make all` - runs fmt, vet, verify, build, test-all)
- [ ] Test with sample Ingress manifest using the tool
- [ ] Verify output contains Gateway, HTTPRoute, and TrafficPolicy

### PR Preparation
- [ ] Commit changes with clear commit messages
- [ ] Push branch to your fork
- [ ] Sign CLA if not already signed
- [ ] Create PR using the PR template
- [ ] Add appropriate labels (e.g., `/kind feature`)
- [ ] Update main README if needed to mention kgateway emitter

## Next Steps (Future PRs)

After this minimal PR is merged, additional CORS annotations can be added:
- `cors-allow-credentials` → TrafficPolicy.spec.cors.httpCORSFilter.allowCredentials
- `cors-allow-headers` → TrafficPolicy.spec.cors.httpCORSFilter.allowHeaders
- `cors-expose-headers` → TrafficPolicy.spec.cors.httpCORSFilter.exposeHeaders
- `cors-allow-methods` → TrafficPolicy.spec.cors.httpCORSFilter.allowMethods
- `cors-max-age` → TrafficPolicy.spec.cors.httpCORSFilter.maxAge

Other annotation categories:
- Rate limiting → TrafficPolicy
- SSL redirect → HTTPRoute filters
- Session affinity → BackendConfigPolicy
- Access logging → HTTPListenerPolicy
- etc.

## Notes

- The provider (`ingress-nginx`) already parses CORS annotations and populates `Policy.Cors` in the IR
- The emitter only needs to read from the IR and generate kgateway resources
- Keep the implementation minimal - focus on `enable-cors` and `cors-allow-origin` for the initial PR
- For minimal implementation, we can simplify CORS handling:
  - Only process `AllowOrigin` (required) - this is the minimum needed for CORS to work
  - Skip optional fields (AllowHeaders, ExposeHeaders, AllowMethods, AllowCredentials, MaxAge) for now
  - These can be added in follow-up PRs
- **Note**: The existing codebase has full CORS support. For the minimal PR, we'll create a simplified version that only handles the core `AllowOrigin` field. This demonstrates the pattern without the complexity of all optional fields.
- Follow existing code patterns from other emitters (e.g., `standard`, `gce`)
- TrafficPolicy attachment logic:
  - If policy covers all backends → use `targetRefs` pointing to HTTPRoute
  - If policy covers specific backends → use `ExtensionRef` filters on those backendRefs

