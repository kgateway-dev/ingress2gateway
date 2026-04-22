# Gloo Edge Provider

This provider enables conversion of Gloo Edge VirtualService resources to Kubernetes Gateway API HTTPRoute manifests.

## Features (MVP)

- Read VirtualService CRDs from cluster or file
- Map hosts to HTTPRoute hostnames
- Convert prefix-based routing rules
- Reference backend services as Kubernetes Services

## Usage

```bash
ingress2gateway print\
  --provider gloo-edge \
  --input-file virtualservice.yaml \
```

## Supported Gloo Edge Features

### Routing
- ✅ `spec.hosts[]` → HTTPRoute `hostnames`
- ✅ `spec.virtualHost.routes[].matchers[].prefix` → HTTPRoute `path` matches
- ✅ `spec.virtualHost.routes[].routeAction.single.upstream` → HTTPRoute backend refs

### Not Yet Supported
- Advanced matchers (header, method, regex)
- Traffic policies (timeout, retry)
- Authentication (OAuth, JWT)
- Canary deployments
- Plugins and filters

## Example

See `test_virtualservice.yaml` for a complete example.