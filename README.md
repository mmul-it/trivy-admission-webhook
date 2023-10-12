# Trivy Kubernetes Admission webhook

This repository defines an **admission webhook** application that can be used as
a gate for the container images of the Pods declared in a Kubernetes cluster.

## The application

The `app.py` application is written in Python using the [CherryPy](https://docs.cherrypy.dev/en/latest/)
minimalist web framework and is included inside a container available at
[quay.io/mmul/trivy-admission-webhook](https://quay.io/repository/mmul/trivy-admission-webhook).

It supports these environmental variables that affects its behavior:

- `TRIVY_WEBHOOK_SEVERITY` defines the severity to be checked (defaults to
  `CRITICAL`.
- `TRIVY_WEBHOOK_ALLOW_INSECURE_REGISTRIES` enables insecure registries during
  scans (defaults to `False`).
- `TRIVY_WEBHOOK_SSL_IP` defines the IP to listen to (defaults to `0.0.0.0`).
- `TRIVY_WEBHOOK_SSL_PORT` defines the TCP port to listen to (defaults to
  `443`).
- `TRIVY_WEBHOOK_SSL_CERT` defines the SSL certificate used by the Python module
  `pyopenssl` (defaults to `/certs/tls.crt`).
- `TRIVY_WEBHOOK_SSL_KEY` defines the SSL certificate key used by the Python
  module `pyopenssl` (defaults to `/certs/tls.key`).

### Local application testing

To test the application locally, without using a container, you will need a
sample json file to simulate the way Kubernetes engage the service and a couple
of certificates (see how to generate them in the next section).

This can be something similar to this, which is a simplified version of the
json produced by Kubernetes:

```json
{
  "apiVersion": "admission.k8s.io/v1beta1",
  "kind": "AdmissionReview",
  "request": {
    "kind": {
      "group": "",
      "kind": "Pod",
      "version": "v1"
    },
    "namespace": "opa",
    "object": {
      "metadata": {
        "labels": {
          "app": "nginx"
        },
        "name": "nginx",
        "namespace": "opa"
      },
      "spec": {
        "containers": [
          {
            "image": "public.ecr.aws/nginx/nginx:1.18",
            "name": "nginx-1.18"
          },
          {
            "image": "public.ecr.aws/nginx/nginx:1.19",
            "name": "nginx-1.19"
          },
          {
            "image": "public.ecr.aws/nginx/nginx:latest",
            "name": "nginx-latest"
          }
        ]
      }
    },
    "uid": "bbfeef88-d98d-11e8-b280-080027868e77"
  }
}
```

This json should engage the service to analyze three containers:

- `public.ecr.aws/nginx/nginx:1.18`
- `public.ecr.aws/nginx/nginx:1.19`
- `public.ecr.aws/nginx/nginx:latest`

With two of them considered insecure (1.18 and 1.19).

To simulate what happens inside Kubernetes, create a Python Virtual environment
and start the app:

```console
> git clone https://github.com/mmul-it/trivy-admission-webhook
Cloning into 'trivy-admission-webhook'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 27 (delta 11), reused 21 (delta 8), pack-reused 0
Receiving objects: 100% (27/27), 5.65 KiB | 5.65 MiB/s, done.
Resolving deltas: 100% (11/11), done.

> python3 -m python3 -m venv taw

> source taw/bin/activate

(taw) > (taw) rasca@catastrofe [~]> pip3 install -r trivy-admission-webhook/requirements.txt
Collecting CherryPy
...
...

> TRIVY_WEBHOOK_SSL_CERT=<PATH TO YOUR CERTS>/tls.crt \
  TRIVY_WEBHOOK_SSL_KEY=<PATH TO YOUR CERTS>/tls.key \
  TRIVY_WEBHOOK_SSL_PORT=8443 \
  python3 trivy-admission-webhook/app.py
[12/Oct/2023:11:28:30] ENGINE Listening for SIGTERM.
[12/Oct/2023:11:28:30] ENGINE Listening for SIGHUP.
[12/Oct/2023:11:28:30] ENGINE Listening for SIGUSR1.
[12/Oct/2023:11:28:30] ENGINE Bus STARTING
CherryPy Checker:
The Application mounted at '' has an empty config.

[12/Oct/2023:11:28:30] ENGINE Started monitor thread 'Autoreloader'.
[12/Oct/2023:11:28:30] ENGINE Serving on https://0.0.0.0:8443
[12/Oct/2023:11:28:30] ENGINE Bus STARTED
```

Then, in another console, the service could be invoked using `curl`, passing the
json sample above and using `jq` to format the output:

```console
> curl -s -k -X POST -d @<PATH TO YOUR JSON>/sample.json \
    -H "Content-Type: application/json" \
    -X POST \
    https://localhost:8443/validate | \
    jq -r '.response | .status | .message'
```

Response should be something like this:

```console
Check Failed! These are insecure container images: public.ecr.aws/nginx/nginx:1.18, public.ecr.aws/nginx/nginx:1.19
```

## Kubernetes webhook activation

A Kubernetes webhook is a mechanism for extending or customizing the behavior of
the Kubernetes API server. webhooks allow you to *intercept* and *validate*
requests to the API server or mutate them based on defined rules or logic.

At the end of the validation process there is an application, exposed by a
service that can be contacted by the webhook.

The application must communicate using SSL, so it relies on a secret containing
the certificates. This command sequence shows how create a secret named
`trivy-admission-webhook-certs` to generate a certificate for the
`trivy-admission-webhook.trivy-system.svc` service, starting from an existing
*Certification Authority*, in this case the one coming from [Minikube](https://minikube.sigs.k8s.io/docs/start/):

- Generate the key:

  ```console
  > servicename=trivy-admission-webhook.trivy-system.svc

  > openssl genrsa -out webhook.key 2048

  > openssl req -new -key webhook.key -out webhook.csr -subj "/CN=$servicename"

  > openssl x509 -req -extfile <(printf "subjectAltName=DNS:$servicename") \
      -days 3650 \
      -in webhook.csr \
      -CA .minikube/ca.crt \
      -CAkey .minikube/ca.key \
      -CAcreateserial \
      -out webhook.crt
  Signature ok
  subject=CN = trivy-admission-webhook.trivy-system.svc
  Getting CA Private Key
  ```
- Create the secret:

  ```console
  > kubectl create namespace trivy-system
  namespace/trivy-system created

  > kubectl -n trivy-system create secret tls trivy-admission-webhook-certs \
      --key="webhook.key" \
      --cert="webhook.crt"
  secret/trivy-admission-webhook-certs created
  ```
With the secret in place the application can be defined inside a deployment, in
a file named `trivy-admission-webhook.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: trivy-admission-webhook
  name: trivy-admission-webhook
  namespace: trivy-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: trivy-admission-webhook
  template:
    metadata:
      labels:
        app: trivy-admission-webhook
    spec:
      containers:
        - name: trivy-admission-webhook
          image: quay.io/mmul/trivy-admission-webhook
          env:
            - name: "TRIVY_WEBHOOK_ALLOW_INSECURE_REGISTRIES"
              value: "True"
          volumeMounts:
           - name: certs
             mountPath: "/certs"
             readOnly: true
      volumes:
        - name: certs
          secret:
            secretName: trivy-admission-webhook-certs
            optional: true
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: trivy-admission-webhook
  name: trivy-admission-webhook
  namespace: trivy-system
spec:
  ports:
    - name: 443-443
      port: 443
      protocol: TCP
      targetPort: 443
  selector:
    app: trivy-admission-webhook
```

To effectively create the application:

```console
> kubectl create -f trivy-admission-webhook.yaml
deployment.apps/trivy-admission-webhook created
service/trivy-admission-webhook created

> kubectl -n trivy-system get all -l app=trivy-admission-webhook
NAME                                           READY   STATUS    RESTARTS   AGE
pod/trivy-admission-webhook-6d965d5c78-cwxnv   1/1     Running   0          13m

NAME                              TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
service/trivy-admission-webhook   ClusterIP   10.98.90.165   <none>        443/TCP   20m

NAME                                      READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/trivy-admission-webhook   1/1     1            1           20m

NAME                                                 DESIRED   CURRENT   READY   AGE
replicaset.apps/trivy-admission-webhook-6d965d5c78   1         1         1       20m
```

The application will listen inside the cluster at the `443` port of the
Kubernetes service named `trivy-admission-webhook.trivy-system.svc`.

To activate the webhook, a `ValidatingWebhookConfiguration` configuration must
be created in the cluster with a configuration like this one in a file called
`taw-validating-webhook-configuration.yaml`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: "trivy-admission-webhook.trivy-system.svc"
webhooks:
- name: "trivy-admission-webhook.trivy-system.svc"
  rules:
  - apiGroups:   [""]
    apiVersions: ["v1"]
    operations:  ["CREATE"]
    resources:   ["pods"]
    scope:       "Namespaced"
  clientConfig:
    service:
      namespace: "trivy-system"
      name: "trivy-admission-webhook"
      path: /validate
      port: 443
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  timeoutSeconds: 30
```

This will make Kubernetes invoke the `trivy-admission-webhook` service at the
`validate` path for each Pod creation request:

```console
> kubectl create -f taw-validating-webhook-configuration.yaml

> kubectl get ValidatingWebhookConfiguration trivy-admission-webhook.trivy-system.svc
NAME                                       WEBHOOKS   AGE
trivy-admission-webhook.trivy-system.svc   1          7m23s
```

### Kubernetes webhook testing

To test everything two deployments with two different versions of nginx will be
deployed, one with no CRITICAL issues (nginx:latest) and the other with some of
them (nginx:1.18):

```console
> kubectl create namespace myns
namespace/myns created

> kubectl -n myns create deployment nginx-latest --image public.ecr.aws/nginx/nginx:latest
deployment.apps/nginx-latest created

> kubectl -n myns create deployment nginx-insecure --image public.ecr.aws/nginx/nginx:1.18
deployment.apps/nginx-insecure created
```

The result will be just one Pod deployed:

```console
> kubectl -n myns get all
NAME                                READY   STATUS    RESTARTS   AGE
pod/nginx-latest-8586ccc94b-9slg8   1/1     Running   0          103s

NAME                             READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/nginx-insecure   0/1     0            0           94s
deployment.apps/nginx-latest     1/1     1            1           103s

NAME                                        DESIRED   CURRENT   READY   AGE
replicaset.apps/nginx-latest-8586ccc94b     1         1         1       103s
```

Details about what happened can be found inside Kubernetes events:

```console
> kubectl -n myns get events --sort-by='.metadata.creationTimestamp' -A
NAMESPACE      LAST SEEN   TYPE      REASON                    OBJECT                                         MESSAGE
...
...
myns           2m29s       Normal    ScalingReplicaSet         deployment/nginx-latest                        Scaled up replica set nginx-latest-785b998d5d to 1
myns           2m24s       Normal    ScalingReplicaSet         deployment/nginx-insecure                      Scaled up replica set nginx-insecure-79b595ff9b to 1
myns           47s         Normal    SuccessfulCreate          replicaset/nginx-latest-785b998d5d             Created pod: nginx-latest-785b998d5d-wrxvm
myns           47s         Normal    Scheduled                 pod/nginx-latest-785b998d5d-wrxvm              Successfully assigned myns/nginx-latest-785b998d5d-wrxvm to minikube
myns           19s         Warning   FailedCreate              replicaset/nginx-insecure-79b595ff9b           Error creating: admission webhook "trivy-admission-webhook.trivy-system.svc" denied the request: Check Failed! These are insecure container images: public.ecr.aws/nginx/nginx:1.18
myns           46s         Normal    Pulling                   pod/nginx-latest-785b998d5d-wrxvm              Pulling image "public.ecr.aws/nginx/nginx:latest"
myns           36s         Normal    Started                   pod/nginx-latest-785b998d5d-wrxvm              Started container nginx
myns           36s         Normal    Created                   pod/nginx-latest-785b998d5d-wrxvm              Created container nginx
myns           36s         Normal    Pulled                    pod/nginx-latest-785b998d5d-wrxvm              Successfully pulled image "public.ecr.aws/nginx/nginx:latest" in 10.195269829s (10.195289913s including waiting)
```

The `public.ecr.aws/nginx/nginx:1.18` container will not be deployed.

### Kubernetes webhooks documentation

For official documentation and more in-depth information on Kubernetes webhooks,
you can refer to the Kubernetes documentation:

- [Official Kubernetes webhooks Overview](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#webhook)
  to get an overview of the webhook mechanism.
- [Kubernetes Admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
  to get details on admission controllers and how webhooks fit into the process.

These resources will provide comprehensive information about Kubernetes webhooks
and how to use them in your cluster.

## License

MIT

## Author Information

Raoul Scarazzini ([rascasoft](https://github.com/rascasoft))
