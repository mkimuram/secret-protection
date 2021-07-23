# secret-protection

## Overview
The secret-protection controller is an external controller that monitors Secret objects and their referencing objects and blocks deletion of Secrets while they are in-use. KEP for this feature can be found [here](https://github.com/kubernetes/enhancements/pull/2640).
In this branch, protection logic is experimentally delegated to [in-use protector](https://github.com/mkimuram/inuseprotection).
In-use protector adds and removes `k8s.io/in-use-protection` finalizer according to the useeReference.
It adds the finalizer to an object if other objects reference it via useeReference, and removes the finalizer if no object references it.
Secret-protection controller just upates the useeReference.

## Feature status
This project is still pre-alpha. This is just a prototype for discussion purpose.

## Usage
### Prerequisite
In-use protector is deployed.

### Build container 
```
make container-secret-protection-controller
```

### Deploy 
(Above container image needs to be available before below command, such as by running `kind load docker-image`.)
```
kubectl create -f examples/kubernetes/secret-protection-controller/rbac-secret-protection-controller.yaml
kubectl create -f examples/kubernetes/secret-protection-controller/setup-secret-protection-controller.yaml
```

### Undeploy
```
kubectl delete -f examples/kubernetes/secret-protection-controller/setup-secret-protection-controller.yaml
kubectl delete -f examples/kubernetes/secret-protection-controller/rbac-secret-protection-controller.yaml
```

While this controller is deployed, `kubernetes.io/secret-protection` finalizers are added to all secrets, these finalizers are needed to be manually deleted after the controller is undeployed.

## How to test manually
### [Unused case]
It should be deleted immediately.

```
kubectl create secret generic test-secret --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'
kubectl get secret test-secret -o yaml
kubectl delete secret test-secret
```

### [Used by pod case]
It should block deletion of secret until all pods using the secret are deleted.

```
kubectl create secret generic test-secret --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'
kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/pods/inject/secret-pod.yaml
kubectl describe pod secret-test-pod
kubectl delete secret test-secret
kubectl get secret test-secret -o yaml
kubectl delete pod secret-test-pod
kubectl get secret
```

### [Used by CSI PV case]

~~It should block deletion of secret until all PVs using the secret are deleted.
(Below assumes that csi-hostpath driver has already been installed.)~~

> **_NOTE:_** Due to the lack of ability to track reference across namespaces, this case doesn't work well with this implementation(The [version](https://github.com/mkimuram/inuseprotection) without in-use protection works).
It will be technically possible to enable it, however it won't align with garbage collector's behavior (please see Note in [this section](https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection/#owners-and-dependents)).

```
kubectl create secret generic test-secret --from-literal='username=my-app' --from-literal='password=39528$vdg7Jb'

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

kubectl delete secret test-secret
kubectl get secret
kubectl delete pvc test-pv-claim
kubectl get secret
```

