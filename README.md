# externalip-webhook

created to address [CVE-2020-8554](https://www.cvedetails.com/cve/CVE-2020-8554/)

externalip-webhook, is a validating webhook which prevents services from using random external IPs. Cluster administrators
can specify list of CIDRs allowed to be used as external IP by specifying `allowed-external-ip-cidrs` parameter.
Webhook will only allow creation of services which doesn't require external IP or whose external IPs are within the range
specified by the administrator.

This repo is built using [kubebuilder](https://book.kubebuilder.io/).

## Deploying

To restrict external IP to certain CIDRs, uncomment and update `allowed-external-ip-cidrs` in [webhook.yaml](config/webhook/webhook.yaml).

NOTE: If auth-proxy is enabled then update `allowed-external-ip-cidrs` in [metrics_server_auth_proxy.yaml](config/default/metrics_server_auth_proxy_patch.yaml).

#### Deploy pre-built webhook
To deploy the webhook using the manifests in this repo, you must have `kustomize` in your path.
You can download `kustomize` here: https://kubernetes-sigs.github.io/kustomize/installation/

```console
make deploy
```

#### Build and deploy webhook
```console
make docker-build IMG=DOCKER_IMAGE_TAG
make deploy IMG=DOCKER_IMAGE_TAG
```

## Configuration

### Updating webhook namespace
Webhook by default runs under `externalip-validation-system` ns. This can be changed by updating namespace and
namePrefix in [kustomization.yaml](config/default/kustomization.yaml) file.

### Certificate generation for webhook
Webhook certificates can either be generated through cert-manager or by uploading certs. Following section explains how
this can be achieved.

#### Using cert manager
Uncomment all sections with 'CERTMANAGER' in [kustomization.yaml](config/default/kustomization.yaml) file.

#### Uploading webhook certificates
1. Upload certs data (ca.crt, tls.crt and tls.key) as kubernetes secret with name `webhook-server-cert` in namespace
same as [kustomization.yaml](config/default/kustomization.yaml).
2. Update `caBundle` field in [manifests.yaml](config/webhook/manifests.yaml).

### Enabling metrics endpoint
Webhook emits `webhook_failed_request_count` metrics whenever it rejects service creation or update operation.

#### Enabling without auth-proxy
Uncomment `--metrics-addr` and the corresponding section in containers.Port in [webhook.yaml](config/webhook/webhook.yaml).

#### Enabling /metrics with auth-proxy
1. Uncomment all sections with 'METRICS_SERVER_RBAC' in [kustomization.yaml](config/default/kustomization.yaml) file.
2. Create cluster role binding for the cluster role in [auth_proxy_client_clusterrole.yaml](config/metrics_server_rbac/auth_proxy_client_clusterrole.yaml).

### Exporting metrics for Prometheus
Follow the steps mentioned [here](https://book.kubebuilder.io/reference/metrics.html#exporting-metrics-for-prometheus) to export the webhook metrics.

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack](http://slack.k8s.io/)
- [Mailing List](https://groups.google.com/forum/#!forum/kubernetes-dev)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).

[owners]: https://git.k8s.io/community/contributors/guide/owners.md
[Creative Commons 4.0]: https://git.k8s.io/website/LICENSE
