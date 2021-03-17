

[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/betorvs/secret-to-handler)
![Go Test](https://github.com/betorvs/secret-to-handler/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/betorvs/secret-to-handler/workflows/goreleaser/badge.svg)

# secret-to-handler

## Table of Contents
- [Overview](#overview)
- [Files](#files)
- [Usage examples](#usage-examples)
- [Configuration](#configuration)
  - [Asset registration](#asset-registration)
  - [Check definition](#check-definition)
- [Installation from source](#installation-from-source)
- [Additional notes](#additional-notes)
  - [Sensu User and Roles ](#sensu-user-and-roles)
  - [Secret Example](#secret-example)
- [Contributing](#contributing)

## Overview

The secret-to-handler is not a typical [Sensu Check][6] it was created to automate creating sensu configurations from a  Kubernetes Secret.

## Usage examples

```sh
Reads a K8S secret and publish a handler in sensu

Usage:
  secret-to-handler [flags]
  secret-to-handler [command]

Available Commands:
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -F, --add-extra-filter string        Add extra filters to all handlers created by this command. e. fatigue_check,work_hours
  -B, --api-backend-host string        Sensu Go Backend API Host (e.g. 'sensu-backend.example.com') (default "127.0.0.1")
  -k, --api-backend-key string         Sensu Go Backend API Key
  -P, --api-backend-pass string        Sensu Go Backend API Password (default "P@ssw0rd!")
  -p, --api-backend-port int           Sensu Go Backend API Port (e.g. 4242) (default 8080)
  -u, --api-backend-user string        Sensu Go Backend API User (default "admin")
  -c, --config string                  Json template for Sensu Check
  -D, --disabled-label string          Query for disabled label (e.g. sync=disabled)
  -e, --external                       Connect to cluster externally (using kubeconfig)
  -f, --handler-key-file-path string   Handler Key file path to be used instead paste key into handler command
  -h, --help                           help for secret-to-handler
  -i, --insecure-skip-verify           skip TLS certificate verification (not recommended!)
  -C, --kubeconfig string              Path to the kubeconfig file (default $HOME/.kube/config)
  -l, --label-selectors string         Query for labelSelectors (e.g. release=stable,environment=qa)
  -m, --main-handler string            Main handler of type set to add all new handlers (default "all-alerts")
  -N, --namespace string               Namespace to which to limit this check
  -R, --reserved-names string          Reserved Names already in use for Sensu that cannot be used anymore (list splited by comma , )
  -s, --secure                         Use TLS connection to API
  -n, --sensu-namespace string         Namespace to which to limit this check
  -t, --trusted-ca-file string         TLS CA certificate bundle in PEM format

Use "secret-to-handler [command] --help" for more information about a command.

```

## Configuration

### Asset registration

[Sensu Assets][10] are the best way to make use of this plugin. If you're not using an asset, please
consider doing so! If you're using sensuctl 5.13 with Sensu Backend 5.13 or later, you can use the
following command to add the asset:

```
sensuctl asset add betorvs/secret-to-handler
```

If you're using an earlier version of sensuctl, you can find the asset on the [Bonsai Asset Index][https://bonsai.sensu.io/assets/betorvs/secret-to-handler].

### Check definition

```yml
---
type: CheckConfig
api_version: core/v2
metadata:
  name: secret-to-handler
  namespace: default
spec:
  command: secret-to-handler -e -l 'alert_route=1' -n development -c "$(cat config.json)"
  subscriptions:
  - secretwatcher
  runtime_assets:
  - betorvs/secret-to-handler
```

## Installation from source

The preferred way of installing and deploying this plugin is to use it as an Asset. If you would
like to compile and install the plugin from source or contribute to it, download the latest version
or create an executable script from this source.

From the local path of the secret-to-handler repository:

```
go build
```

## Additional notes

### sensu user and roles 

Create a user in Sensu Backend to be used by secret-to-handler:
```
---
type: User
api_version: core/v2
metadata:
  name: secret-to-handler
spec:
  disabled: false
  username: secret-to-handler
  password_hash: $blablabla
---
type: ClusterRole
api_version: core/v2
metadata:
  name: secret-to-handler-role
spec:
  rules:
  - resource_names: []
    resources:
    - filters
    - handlers
    - mutators
    verbs:
    - get
    - list
    - create
    - update
    - delete
---
type: ClusterRoleBinding
api_version: core/v2
metadata:
  name: secret-to-handler-role-binding
spec:
  role_ref:
    name: secret-to-handler-role
    type: ClusterRole
  subjects:
  - name: secret-to-handler
    type: User
```

### secret example

Use `disabled: "true"` to clean up all filters, mutators and handlers from Sensu.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: alert-route-example
  namespace: default
  labels:
    alert_route: "1"
type: Opaque
stringData:
  name: ops
  contacts: ops
  keys: |
    opsgenie: "api-key-long"
    chat: "long-webhook"
  disabled: "false"
```

For this work, we should have assets for [opsgenie][11] and [hangouts chat][12] and asset for secret-to-handler.


## Contributing

For more information about contributing to this plugin, see [Contributing][1].

[1]: https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md
[2]: https://github.com/sensu-community/sensu-plugin-sdk
[3]: https://github.com/sensu-plugins/community/blob/master/PLUGIN_STYLEGUIDE.md
[4]: https://github.com/sensu-community/check-plugin-template/blob/master/.github/workflows/release.yml
[5]: https://github.com/sensu-community/check-plugin-template/actions
[6]: https://docs.sensu.io/sensu-go/latest/reference/checks/
[7]: https://github.com/sensu-community/check-plugin-template/blob/master/main.go
[8]: https://bonsai.sensu.io/
[9]: https://github.com/sensu-community/sensu-plugin-tool
[10]: https://docs.sensu.io/sensu-go/latest/reference/assets/
[11]: https://github.com/betorvs/sensu-opsgenie-handler
[12]: https://github.com/betorvs/sensu-hangouts-chat-handler
