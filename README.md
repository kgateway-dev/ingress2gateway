# Ingress to Gateway

This is a fork of the upstream [ingress2gateway](https://github.com/kubernetes-sigs/ingress2gateway) project
that translates Ingress resources to Gateway API and [Kgateway](https://kgateway.dev/)-specific resources, e.g.
[TrafficPolicy](https://kgateway.dev/docs/envoy/2.0.x/about/policies/trafficpolicy/).

## Providers vs Emitters

Ingress2gateway has two main components: **providers** and **emitters**.

- **Providers** read Ingress resources and provider-specific CRDs, then convert
  them into a generic intermediate representation (IR).
- **Emitters** take that IR and produce the final Gateway API output. The default
  `standard` emitter outputs core Gateway API resources (like `Gateway` and
  `HTTPRoute`), while other emitters can additionally output resources tailored to
  a specific Gateway API project (e.g. `EnvoyGateway` `BackendTrafficPolicy`
  or `GKE` `HealthCheckPolicy`).

For a detailed look at the architecture, see [docs/emitters.md](docs/emitters.md).

### Supported Providers

* [ingress-nginx](pkg/i2gw/providers/ingressnginx/README.md)
* [gloo-edge](pkg/i2gw/providers/glooedge/README.md)
If your provider, or a specific feature, is not currently supported, please open
an issue and describe your use case.

## Supported emitters

* [agentgateway](pkg/i2gw/emitters/agentgateway/README.md)
* [kgateway](pkg/i2gw/emitters/kgateway/README.md)

If your emitter, or a specific feature, is not currently supported, please open
an issue and describe your use case.

## Installation

### Via go install

If you have a Go development environment locally, you can install ingress2gateway
with `go install github.com/kgateway-dev/ingress2gateway@v0.1.0`

This will put `ingress2gateway` binary in `$(go env GOPATH)/bin`

Alternatively, you can download the binary at the [releases page](https://github.com/kgateway-dev/ingress2gateway/releases)

### Build from Source

1. Ensure that your system meets the following requirements:

   * Install Git: Make sure Git is installed on your system to clone the project
     repository.
   * Install Go 1.25.5 or later: Make sure the Go language is installed on your
     system. You can download it from the official website
     (https://golang.org/dl/) and follow the installation instructions.

1. Clone the project repository

   ```shell
   git clone https://github.com/kgateway-dev/ingress2gateway.git && cd ingress2gateway
   ```

1. Build the project

   ```shell
   make build
   ```

1. Install the binary to your system

   ```shell
   go install .
   ```

## Usage

Ingress2gateway reads Ingress resources from a Kubernetes cluster or a file. It will output the equivalent
Gateway API and Kgateway-specific resources in a YAML/JSON format to stdout.  The simplest case is to convert
all ingresses from the ingress-nginx provider:

```shell
./ingress2gateway print --providers=ingress-nginx --emitter=kgateway
```
to convert Gloo Edge VirtualService

```shell
./ingress2gateway print --providers=gloo-edge --emitter=kgateway
```

The above command will:

1. Read your Kube config file to extract the cluster credentials and the current
   active namespace.
2. Search for ingress-nginx resources in that namespace.
3. Convert them to Gateway-API resources (Currently only Gateways and HTTPRoutes).

## Options

### `print` command

| Flag           | Short | Default Value           | Required | Description                                                  |
| -------------- | ----- | ----------------------- | -------- | ------------------------------------------------------------ |
| all-namespaces | -A    | false                   | No       | If present, list the requested object(s) across all namespaces. Namespace in the current context is ignored even if specified with --namespace. |
| allow-experimental-gw-api | | false              | No       | If present, include Experimental Gateway API fields (e.g. URLRewrite) in the output. |
| emitter        |       | standard                | No       | The emitter to use for generating Gateway API resources.      |
| input-file     |       |                         | No       | Path to the manifest file(s). When set, the tool will read ingresses from the file(s) instead of reading from the cluster. Supports yaml and json. Can be specified multiple times. |
| kubeconfig     |       |                         | No       | The kubeconfig file to use when talking to the cluster. If the flag is not set, a set of standard locations can be searched for an existing kubeconfig file. |
| namespace      | -n    |                         | No       | If present, the namespace scope for the invocation.           |
| no-color       |       | false                   | No       | Disable ANSI color codes in the output.                       |
| output         | -o    | yaml                    | No       | The output format. One of: yaml, json, kyaml.                 |
| providers      |       |                         | Yes      | Comma-separated list of providers.                            |

#### Provider-specific flags

| Flag           | Default Value           | Required | Description                                                  |
| -------------- | ----------------------- | -------- | ------------------------------------------------------------ |
| all-namespaces | False                   | No       | If present, list the requested object(s) across all namespaces. Namespace in the current context is ignored even if specified with --namespace. |
| input-file     |                         | No       | Path to the manifest file. When set, the tool will read ingresses from the file instead of reading from the cluster. Supported files are yaml and json. |
| namespace      |                         | No       | If present, the namespace scope for the invocation.           |
| output         | yaml                    | No       | The output format, either yaml or json.                       |
| providers      |  | Yes       | Comma-separated list of providers (ingress-nginx and Gloo-edge is supported). |
| emitter      | standard | No       | The emitter to use for generating Gateway API resources (supported values: standard, kgateway). |
| kubeconfig     |                         | No       | The kubeconfig file to use when talking to the cluster. If the flag is not set, a set of standard locations can be searched for an existing kubeconfig file. |

## Conversion of Ingress resources to Gateway API

### Processing Order and Conflicts

Ingress resources will be processed with a defined order to ensure deterministic
generated Gateway API configuration.
This should also determine precedence order of Ingress resources and routes in case
of conflicts.

Ingress resources with the oldest creation timestamp will be sorted first and therefore
given precedence. If creation timestamps are equal, then sorting will be done based
on the namespace/name of the resources. If an Ingress rule conflicts with another
(e.g. same path match but different backends) an error will be reported for the
one that sorted later.

Since the Ingress v1 spec does not itself have a conflict resolution guide, we have
adopted this one. These rules are similar to the [Gateway API conflict resolution
guidelines](https://gateway-api.sigs.k8s.io/concepts/guidelines/#conflicts).
# Provider-Specific Conversions

## Ingress-Nginx

Ingress resources will be converted to Gateway API resources as follows:

| Ingress Field                   | Gateway API configuration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ingressClassName`              | If configured on an Ingress resource, this value will be translated to the corresponding Gateway class.                                                                                                                                                                                                                                                                                                                                                                                               |
| `defaultBackend`                | If present, this configuration will generate a Gateway Listener with no `hostname` specified as well as a catchall HTTPRoute that references this listener. The backend specified here will be translated to a HTTPRoute `rules[].backendRefs[]` element.                                                                                                                                                                                                                                                                                                                                                         |
| `tls[].hosts`                   | Each host in an IngressTLS will result in a HTTPS Listener on the generated Gateway with the following: `listeners[].hostname` = host as described, `listeners[].port` = `443`, `listeners[].protocol` = `HTTPS`, `listeners[].tls.mode` = `Terminate`                                                                                                                                                                                                                                                                                                                                                            |
| `tls[].secretName`              | The secret specified here will be referenced in the Gateway HTTPS Listeners mentioned above with the field `listeners[].tls.certificateRefs`. Each Listener for each host in an IngressTLS will get this secret.                                                                                                                                                                                                                                                                                                                                                                                                  |
| `rules[].host`                  | If non-empty, each distinct value for this field in the provided Ingress resources will result in a separate Gateway HTTP Listener with matching `listeners[].hostname`. `listeners[].port` will be set to `80` and `listeners[].protocol` set to `HTTP`. In addition, Ingress rules with the same hostname will generate HTTPRoute rules in a HTTPRoute with `hostnames` containing it as the single element. If empty, similar to the `defaultBackend`, a Gateway Listener with no hostname configuration will be generated (if it doesn't exist) and routing rules will be generated in a catchall HTTPRoute. |
| `rules[].http.paths[].path`     | This field translates to a HTTPRoute `rules[].matches[].path.value` configuration.                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `rules[].http.paths[].pathType` | This field translates to a HTTPRoute `rules[].matches[].path.type` configuration. Ingress `Exact` = HTTPRoute `Exact` match. Ingress `Prefix` = HTTPRoute `PathPrefix` match.                                                                                                                                                                                                                                                                                                                                     |
| `rules[].http.paths[].backend`  | The backend specified here will be translated to a HTTPRoute `rules[].backendRefs[]` element.                                                                                                                                                                                                                                                                                                                                                                                                                     |

## Gloo Edge

Gloo Edge VirtualServices will be converted to Gateway API resources as follows:

| VirtualService Field                           | Gateway API configuration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.hosts`                                   | Each host in the VirtualService hosts list will result in a separate Gateway HTTP Listener with matching `listeners[].hostname`. `listeners[].port` will be set to `80` and `listeners[].protocol` set to `HTTP`. HTTPRoute resources will be created with `hostnames` containing the corresponding host as the single element.                                                                                                                                                                                                                                                                                   |
| `spec.virtualHost.routes[].matchers[].prefix` | This field translates to a HTTPRoute `rules[].matches[].path.value` configuration with `type` set to `PathPrefix`.                                                                                                                                                                                                                                                                                                                                                                                                                |
| `spec.virtualHost.routes[].routeAction.single.upstream` | The upstream specified here will be translated to a HTTPRoute `rules[].backendRefs[]` element with the upstream name as the backend Service name.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `spec.virtualHost.routes[].routeAction.single.upstream.port` | The port specified on the upstream will be translated to the HTTPRoute backend ref `port` field.                                                                                                                                                                                                                                                                                                                                                                                                                                |
