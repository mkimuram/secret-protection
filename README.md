# secret-protection

## Overview
The secret-protection controller is an external controller that monitors Secret objects and their referencing objects and blocks deletion of Secrets while they are in-use. This feature is being discussd in [KEP-2639](https://github.com/kubernetes/enhancements/pull/2640).
In this branch, protection logic is experimentally delegated to Lien that is being discussed in [KEP-2839](https://github.com/kubernetes/enhancements/pull/2840) and prototyped [here](https://github.com/mkimuram/kubernetes/commits/lienv2-forcedel).

In Lien, a new field `Liens` is introduced in Object's Metadata as a slice of strings, like `Finalizers`.
Users or controllers can add/remove the field to ask to block the deletion request of the object.
The deletion request to an object is blocked by lien validating admission webhook, until the last `Liens` of the object is deleted.

By using the Lien, secret-protection controller provides a protection mechanism for secrets.
It upates the `Liens` field of secrets when it has a referencing object.
`kubernetes.io/secret-protection` lien is added when the secret is used.

## Feature status
This project is still pre-alpha. This is just a prototype for discussion purpose.

## Usage
### Prerequisite
A cluster with Lien is deployed.

```bash
git clone --single-branch --depth 5 --branch lienv2-forcedel https://github.com/mkimuram/kubernetes.git
cd kubernetes/
FEATURE_GATES=InUseProtection=true hack/local-up-cluster.sh
```

### Build container 
- Clone this branch
```bash
git clone --single-branch --branch lienv2 https://github.com/mkimuram/secret-protection.git
cd secret-protection/
```

- Update go.mod to use the version of k8s.io/apimachinery in the above k8s repo
```bash
k8ssrc=~/work/kubernetes
go mod edit -replace k8s.io/apimachinery=${k8ssrc}/staging/src/k8s.io/apimachinery/
go mod tidy
```

- Build the secret protection controller container
```bash
make container-secret-protection-controller
```

### Deploy 
(Above container image needs to be available before below command. Note that k8s cluster deployed by local-up-cluster.sh satisfies this requirement.)
```
kubectl create -f examples/kubernetes/secret-protection-controller/rbac-secret-protection-controller.yaml
kubectl create -f examples/kubernetes/secret-protection-controller/setup-secret-protection-controller.yaml
```

### Undeploy
```
kubectl delete -f examples/kubernetes/secret-protection-controller/setup-secret-protection-controller.yaml
kubectl delete -f examples/kubernetes/secret-protection-controller/rbac-secret-protection-controller.yaml
```

While this controller is deployed, Liens that are prefixed with `kubernetes.io/secret-protection` are added to the secrets that are used by other resources, these Liens are needed to be manually deleted after the controller is undeployed.

## How to test manually
### [Unused case]
It should be deleted immediately.

```
kubectl create secret generic test-secret --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'
kubectl annotate secrets test-secret kubernetes.io/enable-secret-protection=yes
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'

kubectl delete secret test-secret
```

### [Used by pod case]
It should block deletion of secret until all pods using the secret are deleted.

```
kubectl create secret generic test-secret --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'
kubectl annotate secrets test-secret kubernetes.io/enable-secret-protection=yes
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'
kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/pods/inject/secret-pod.yaml
kubectl describe pod secret-test-pod
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'
[kubernetes.io/secret-protection]
kubectl delete secret test-secret
Error from server (Forbidden): secrets "test-secret" is forbidden: deletion not allowed by liens
kubectl delete pod secret-test-pod
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'

kubectl delete secret test-secret
secret "test-secret" deleted
```

### [Used by CSI PV case]

It should block deletion of secret until all PVs using the secret are deleted.
(Below assumes that csi-hostpath driver has already been installed.)

```
kubectl create secret generic test-secret --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'
kubectl annotate secrets test-secret kubernetes.io/enable-secret-protection=yes

cat << 'EOF' | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: csi-hostpath-sc-with-secret
provisioner: hostpath.csi.k8s.io
parameters:
  csi.storage.k8s.io/node-publish-secret-namespace: ${pvc.namespace}
  csi.storage.k8s.io/node-publish-secret-name: test-secret
EOF

cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pv-claim
spec:
  storageClassName: csi-hostpath-sc-with-secret
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
EOF

kubectl get pv -o yaml | grep -A 5 " csi:"
    csi:
      driver: hostpath.csi.k8s.io
      nodePublishSecretRef:
        name: test-secret
        namespace: default
      volumeAttributes:

kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'
[kubernetes.io/secret-protection]

kubectl annotate secrets test-secret kubernetes.io/enable-secret-protection-
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'

kubectl annotate secrets test-secret kubernetes.io/enable-secret-protection=yes
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'
[kubernetes.io/secret-protection]

kubectl delete secret test-secret
Error from server (Forbidden): secrets "test-secret" is forbidden: deletion not allowed by liens

kubectl delete pvc test-pv-claim
kubectl get secret test-secret -o jsonpath='{.metadata.liens}{"\n"}'

kubectl delete secret test-secret
secret "test-secret" deleted
```

