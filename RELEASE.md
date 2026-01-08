# Releasing Ingress2Gateway

## Overview

This is a downstream of the [Ingress2Gateway](https://github.com/kgateway-dev/ingress2gateway) project. Ingress2Gateway is a
CLI tool that helps translate Ingress and provider related resources to
[Gateway API](https://github.com/kubernetes-sigs/gateway-api) and Kgateway-specific resources.

## Releasing a new version

### Prerequisites

1. Permissions to push to the repository.

2. Set the required environment variables based on the expected release number:

   ```shell
   export MAJOR=0
   export MINOR=3
   export PATCH=0
   export RC=1
   export REMOTE=origin
   ```

  __Note:__ The above example assumes `origin` is the name of the `https://github.com/kgateway-dev/ingress2gateway.git` remote.

### Release Process

1. If needed, clone the repository.

   ```shell
   git clone -o ${REMOTE} https://github.com/kgateway-dev/ingress2gateway.git
   ```

2. If you already have the repo cloned, ensure it’s up-to-date and your local branch is clean.

3. Release Branch Handling:

   - __For a Release Candidate:__
     A release branch should already exist and contain backported commits since the previous relates tag. In this case, check out the existing branch:

     ```shell
     git checkout -b release-${MAJOR}.${MINOR} ${REMOTE}/release-${MAJOR}.${MINOR}
     ```

   - __For a Major, Minor or Patch Release:__
     Create a new release branch from the `main` branch. The branch should be named `release-${MAJOR}.${MINOR}`, for example, `release-0.1`:

     ```shell
     git checkout -b release-${MAJOR}.${MINOR}
     ```

4. Set the version of the binary by updating `CurrentVersion` in [pkg/i2gw/ingress2gateway.go](pkg/i2gw/ingress2gateway.go) to
   match the version set in the above environment variables. This will allow the ingress2Gateway binary to print the correct version. For example:

    ```bash
    $ ingress2gateway version
    ingress2gateway version: v0.1.0
    Built with Go version: go1.25.3
    ```

5. Commit your changes

    ```bash
    git add pkg/i2gw/ingress2gateway.go && git commit -s -m "Sets version of ingress2gateway binary"
    ```

6. Push your release branch to the `kgateway-dev/ingress2gateway` repo.

    ```shell
    git push ${REMOTE} release-${MAJOR}.${MINOR}
    ```

7. Tag the head of your release branch with the release version.

   For a release candidate:

    ```shell
    git tag -s -a v${MAJOR}.${MINOR}.${PATCH}-rc.${RC} -m 'Ingress2Gateway v${MAJOR}.${MINOR}.${PATCH}-rc.${RC} Release Candidate'
    ```

   For a major, minor or patch release:

    ```shell
    git tag -s -a v${MAJOR}.${MINOR}.${PATCH} -m 'Ingress2Gateway v${MAJOR}.${MINOR}.${PATCH} Release'
    ```

8. Push the tag to the `kgateway-dev/ingress2gateway` repo.

   __For a release candidate:__

    ```shell
    git push ${REMOTE} v${MAJOR}.${MINOR}.${PATCH}-rc.${RC}
    ```

   __For a major, minor or patch release:__

    ```shell
    git push ${REMOTE} v${MAJOR}.${MINOR}.${PATCH}
    ```

9. Verify the release has been published to the [releases page](https://github.com/kgateway-dev/ingress2gateway/releases).

10. Download and verify the binary version, e.g. `ingress2gateway version`.

    ```bash
    ingress2gateway version
    ```

11. If you find any bugs in this process, create an [issue](https://github.com/kgateway-dev/ingress2gateway/issues).
