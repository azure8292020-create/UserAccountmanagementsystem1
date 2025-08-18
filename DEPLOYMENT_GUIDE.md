# User Account Management System Deployment Guide

## Prerequisites
- Docker installed
- Access to a container registry (DockerHub, ECR, GCR, etc.)
- Kubernetes cluster with Istio and Helm installed
- DNS for your Istio ingress gateway

## 1. Build and Push Docker Image

```
docker build -t <your-docker-repo>/user-account-management:latest .
docker push <your-docker-repo>/user-account-management:latest
```

## 2. Prepare Helm Values

- Copy `charts/user-account-management/values-sample.yaml` to `values.yaml` and edit:
  - Set `image.repository` and `image.tag`
  - Set AD server details, certs, and credentials
  - Set admin username, password, and email
  - Set Istio hostnames and gateway

## 3. Add AD Certificates as Kubernetes Secrets

Encode your AD certs in base64 and add to the `secret-ad-certs.yaml` or create the secret manually:

```
kubectl create secret generic user-account-management-ad-certs \
  --from-file=ad1.crt=</path/to/ad1.crt> \
  --from-file=ad2.crt=</path/to/ad2.crt> \
  -n <your-namespace>
```

## 4. Deploy with Helm

```
cd charts/user-account-management
helm dependency update
helm install user-account-management . --namespace <your-namespace> --create-namespace -f values.yaml
```

## 5. Configure DNS and Istio

- Ensure your DNS points to the Istio ingress gateway external IP.
- The app will be available at `https://<your-configured-hostname>`.

## 6. Access and Use the Application

- Visit the app URL in your browser.
- Log in as admin to generate registration codes and approve users.
- Use the reporting UI for audits and exports.

## 7. Maintenance

- Monitor logs and application health.
- Rotate secrets and registration codes as needed.
- Use the admin UI for user and code management.

---

For troubleshooting or advanced configuration, see the README or contact your DevOps team.
