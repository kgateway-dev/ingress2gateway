# Minimal Kgateway Emitter Implementation Summary

This document summarizes the minimal kgateway emitter implementation for the PR to `kubernetes-sigs/ingress2gateway`.

## Current Status

The kgateway emitter already exists in this repository with full feature support. For the initial PR to `kubernetes-sigs/ingress2gateway`, we want to submit a **minimal version** that includes:

1. Basic emitter scaffolding
2. Support for CORS with `AllowOrigin` only

## Files Required for Minimal PR

### 1. `pkg/i2gw/emitters/kgateway/emitter.go`
- `init()`: Register emitter
- `NewEmitter()`: Constructor
- `Emit()`: Main logic - simplified to only handle CORS

### 2. `pkg/i2gw/emitters/kgateway/types.go`
- `TrafficPolicyGVK`: GVK definition

### 3. `pkg/i2gw/emitters/kgateway/utils.go`
- `ensureTrafficPolicy()`: Helper to create/get TrafficPolicy
- `uniquePolicyIndices()`: Deduplicate policy indices
- `numRules()`: Count backend refs
- `toUnstructured()`: Convert to unstructured

### 4. `pkg/i2gw/emitters/kgateway/cors.go`
- `applyCorsPolicy()`: Simplified to only handle `AllowOrigin`
- Skip optional fields (AllowHeaders, ExposeHeaders, AllowMethods, AllowCredentials, MaxAge)

### 5. `cmd/print.go`
- Already imports kgateway emitter (line 40)

### 6. `pkg/i2gw/emitters/kgateway/README.md`
- Document minimal implementation

## Simplifications Needed

To create the minimal version, the existing `emitter.go` should be simplified to:

1. Remove all policy applications except CORS
2. Remove BackendConfigPolicy, HTTPListenerPolicy, GatewayExtension, Backend tracking
3. Remove SSL redirect splitting
4. Keep only TrafficPolicy creation and attachment logic

The existing `cors.go` should be simplified to:

1. Only process `AllowOrigin` field
2. Remove processing of optional CORS fields
3. Keep the basic TrafficPolicy creation

## Next Steps

1. Check if kgateway emitter exists in `kubernetes-sigs/ingress2gateway`
2. If it doesn't exist, create minimal versions of the files
3. If it exists, determine if we're extending it or replacing it
4. Create PR with minimal implementation
5. Follow-up PRs can add additional features

