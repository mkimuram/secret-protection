/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package secretprotection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	storageinformers "k8s.io/client-go/informers/storage/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	storageListers "k8s.io/client-go/listers/storage/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/component-base/metrics/prometheus/ratelimiter"
	"k8s.io/klog/v2"
)

const (
	// SecretProtectionFinalizer is the name of finalizer on secrets that are consumed by the other resources
	SecretProtectionLienID                  = "kubernetes.io/secret-protection"
	deprecatedProvisionerSecretNameKey      = "provisioner-secret-name"
	deprecatedProvisionerSecretNamespaceKey = "provisioner-secret-namespace"
	provisionerSecretNameKey                = "csi.storage.k8s.io/provisioner-secret-name"
	provisionerSecretNamespaceKey           = "csi.storage.k8s.io/provisioner-secret-namespace"

	tokenPVNameKey       = "pv.name"
	tokenPVCNameKey      = "pvc.name"
	tokenPVCNamespaceKey = "pvc.namespace"

	useeReferenceKey = "k8s.io/useereference"
)

// Controller is controller that removes SecretProtectionFinalizer
// from secrets that are used by no other resources.
type Controller struct {
	client         clientset.Interface
	metadataClient metadata.Interface

	secretLister       corelisters.SecretLister
	secretListerSynced cache.InformerSynced

	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	pvLister       corelisters.PersistentVolumeLister
	pvListerSynced cache.InformerSynced

	pvcLister       corelisters.PersistentVolumeClaimLister
	pvcListerSynced cache.InformerSynced

	scLister       storageListers.StorageClassLister
	scListerSynced cache.InformerSynced

	podQueue       workqueue.RateLimitingInterface
	pvQueue        workqueue.RateLimitingInterface
	podDeleteQueue workqueue.RateLimitingInterface
	pvDeleteQueue  workqueue.RateLimitingInterface

	// allows overriding of StorageObjectInUseProtection feature Enabled/Disabled for testing
	storageObjectInUseProtectionEnabled bool
}

// NewSecretProtectionController returns a new instance of SecretProtectionController.
func NewSecretProtectionController(secretInformer coreinformers.SecretInformer, podInformer coreinformers.PodInformer, pvInformer coreinformers.PersistentVolumeInformer, pvcInformer coreinformers.PersistentVolumeClaimInformer, scInformer storageinformers.StorageClassInformer, cl clientset.Interface, metadataCl metadata.Interface, storageObjectInUseProtectionFeatureEnabled bool) *Controller {
	e := &Controller{
		client:                              cl,
		metadataClient:                      metadataCl,
		podQueue:                            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_pod"),
		pvQueue:                             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_pv"),
		podDeleteQueue:                      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_pod_delete"),
		pvDeleteQueue:                       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_pv_delete"),
		storageObjectInUseProtectionEnabled: storageObjectInUseProtectionFeatureEnabled,
	}
	if cl != nil && cl.CoreV1().RESTClient().GetRateLimiter() != nil {
		ratelimiter.RegisterMetricAndTrackRateLimiterUsage("secret_protection_controller", cl.CoreV1().RESTClient().GetRateLimiter())
	}

	e.secretLister = secretInformer.Lister()
	e.secretListerSynced = secretInformer.Informer().HasSynced

	e.podLister = podInformer.Lister()
	e.podListerSynced = podInformer.Informer().HasSynced
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: e.podAddedUpdated,
		UpdateFunc: func(old, new interface{}) {
			e.podAddedUpdated(new)
		},
		DeleteFunc: e.podDeleted,
	})

	e.pvLister = pvInformer.Lister()
	e.pvListerSynced = pvInformer.Informer().HasSynced
	pvInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: e.pvAddedUpdated,
		UpdateFunc: func(old, new interface{}) {
			e.pvAddedUpdated(new)
		},
		DeleteFunc: e.pvDeleted,
	})

	e.pvcLister = pvcInformer.Lister()
	e.pvcListerSynced = pvcInformer.Informer().HasSynced

	e.scLister = scInformer.Lister()
	e.scListerSynced = scInformer.Informer().HasSynced

	return e
}

// Run runs the controller goroutines.
func (c *Controller) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.podQueue.ShutDown()
	defer c.pvQueue.ShutDown()
	defer c.podDeleteQueue.ShutDown()
	defer c.pvDeleteQueue.ShutDown()

	klog.InfoS("Starting secret protection controller")
	defer klog.InfoS("Shutting down secret protection controller")

	if !cache.WaitForNamedCacheSync("secret protection", stopCh, c.secretListerSynced, c.podListerSynced, c.pvcListerSynced, c.scListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.runPodWorker, time.Second, stopCh)
		go wait.Until(c.runPvWorker, time.Second, stopCh)
		go wait.Until(c.runPodDeleteWorker, time.Second, stopCh)
		go wait.Until(c.runPvDeleteWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) runPodWorker() {
	for c.processNextPodWorkItem() {
	}
}

// processNextPodWorkItem deals with one podKey off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextPodWorkItem() bool {
	podKey, quit := c.podQueue.Get()
	if quit {
		return false
	}
	defer c.podQueue.Done(podKey)

	podNamespace, podName, err := cache.SplitMetaNamespaceKey(podKey.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error parsing pod key %q: %v", podKey, err))
		return true
	}

	err = c.processPod(podNamespace, podName)
	if err == nil {
		c.podQueue.Forget(podKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("pod %v failed with : %v", podKey, err))
	c.podQueue.AddRateLimited(podKey)

	return true
}

func (c *Controller) processPod(podNamespace, podName string) error {
	klog.V(4).InfoS("Processing pod", "pod", klog.KRef(podNamespace, podName))
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished processing pod", "pod", klog.KRef(podNamespace, podName), "duration", time.Since(startTime))
	}()

	pod, err := c.podLister.Pods(podNamespace).Get(podName)
	if apierrors.IsNotFound(err) {
		klog.V(4).InfoS("Pod not found, ignoring", "pod", klog.KRef(podNamespace, podName))
		return nil
	}
	if err != nil {
		return err
	}

	// Find secrets used by this Pod
	hasErr := false
	resourceID := toPodResourceID(pod.Namespace, pod.Name)
	for _, volume := range pod.Spec.Volumes {
		switch {
		case volume.Secret != nil:
			secret, err := c.secretLister.Secrets(pod.Namespace).Get(volume.Secret.SecretName)
			if err != nil {
				if apierrors.IsNotFound(err) {
					klog.V(4).InfoS("Secret not found", "secret", klog.KRef(pod.Namespace, volume.Secret.SecretName))
				}
				hasErr = true
				continue
			}

			if err := c.updateLiensForSecret(secret, resourceID); err != nil {
				hasErr = true
			}
		}
	}

	// There are errors in adding Liens to any of the secrets, so return error to retry later.
	if hasErr {
		return fmt.Errorf("error adding liens for secrets used by Pod %s/%s", podNamespace, podName)
	}

	return nil
}

func (c *Controller) runPvWorker() {
	for c.processNextPvWorkItem() {
	}
}

// processNextPvWorkItem deals with one pvKey off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextPvWorkItem() bool {
	pvKey, quit := c.pvQueue.Get()
	if quit {
		return false
	}
	defer c.pvQueue.Done(pvKey)

	pvNamespace, pvName, err := cache.SplitMetaNamespaceKey(pvKey.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error parsing pv key %q: %v", pvKey, err))
		return true
	}

	err = c.processPv(pvNamespace, pvName)
	if err == nil {
		c.pvQueue.Forget(pvKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("pv %v failed with : %v", pvKey, err))
	c.pvQueue.AddRateLimited(pvKey)

	return true
}

func (c *Controller) processPv(pvNamespace, pvName string) error {
	klog.V(4).InfoS("Processing pv", "pv", klog.KRef(pvNamespace, pvName))
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished processing pv", "pv", klog.KRef(pvNamespace, pvName), "duration", time.Since(startTime))
	}()

	pv, err := c.pvLister.Get(pvName)
	if apierrors.IsNotFound(err) {
		klog.V(4).InfoS("Pv not found, ignoring", "pv", klog.KRef(pvNamespace, pvName))
		return nil
	}
	if err != nil {
		return err
	}

	// Find secrets used by this PV
	hasErr := false
	resourceID := toPvResourceID(pv.Name)

	for _, key := range c.getSecretsUsedByPV(pv) {
		secretNamespace, secretName, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("error parsing secret key %q: %v", key, err))
			hasErr = true
			continue
		}
		secret, err := c.secretLister.Secrets(secretNamespace).Get(secretName)

		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.V(4).InfoS("Secret not found", "secret", klog.KRef(secretNamespace, secretName))
			}
			hasErr = true
			continue
		}

		if err := c.updateLiensForSecret(secret, resourceID); err != nil {
			hasErr = true
		}
	}

	// There are errors in adding Liens to any of the secrets, so return error to retry later.
	if hasErr {
		return fmt.Errorf("error adding liens for secrets used by PersistentVolume %s", pvName)
	}

	return nil
}

func (c *Controller) runPodDeleteWorker() {
	for c.processNextPodDeleteWorkItem() {
	}
}

// processNextPodDeleteWorkItem deals with one podKey off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextPodDeleteWorkItem() bool {
	podKey, quit := c.podDeleteQueue.Get()
	if quit {
		return false
	}
	defer c.podDeleteQueue.Done(podKey)

	podNamespace, podName, err := cache.SplitMetaNamespaceKey(podKey.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error parsing pod key %q: %v", podKey, err))
		return true
	}

	err = c.processPodDelete(podNamespace, podName)
	if err == nil {
		c.podDeleteQueue.Forget(podKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("pod %v delete event failed with : %v", podKey, err))
	c.podDeleteQueue.AddRateLimited(podKey)

	return true
}

func (c *Controller) processPodDelete(podNamespace, podName string) error {
	klog.V(4).InfoS("Processing pod delete", "pod", klog.KRef(podNamespace, podName))
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished processing pod delete", "pod", klog.KRef(podNamespace, podName), "duration", time.Since(startTime))
	}()

	// Find secrets that is used by this Pod, and remove Liens
	secrets, err := c.secretLister.List(labels.NewSelector())
	if err != nil {
		return err
	}

	resourceID := toPodResourceID(podNamespace, podName)
	hasErr := false

	for _, secret := range secrets {
		err := c.deleteLiensForSecret(secret, resourceID)
		if err != nil {
			hasErr = true
		}
	}

	// There are errors in deleting Liens to any of the secrets, so return error to retry later.
	if hasErr {
		return fmt.Errorf("error deleting liens for secrets used by Pod %s/%s", podNamespace, podName)
	}

	return nil
}

func (c *Controller) runPvDeleteWorker() {
	for c.processNextPvDeleteWorkItem() {
	}
}

// processNextPvDeleteWorkItem deals with one pvKey off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextPvDeleteWorkItem() bool {
	pvKey, quit := c.pvDeleteQueue.Get()
	if quit {
		return false
	}
	defer c.pvDeleteQueue.Done(pvKey)

	pvNamespace, pvName, err := cache.SplitMetaNamespaceKey(pvKey.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error parsing pv key %q: %v", pvKey, err))
		return true
	}

	err = c.processPvDelete(pvNamespace, pvName)
	if err == nil {
		c.pvDeleteQueue.Forget(pvKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("pv %v delete event failed with : %v", pvKey, err))
	c.pvDeleteQueue.AddRateLimited(pvKey)

	return true
}

func (c *Controller) processPvDelete(pvNamespace, pvName string) error {
	klog.V(4).InfoS("Processing pv delete", "pv", klog.KRef(pvNamespace, pvName))
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished processing pv delete", "pv", klog.KRef(pvNamespace, pvName), "duration", time.Since(startTime))
	}()

	// Find secrets that is used by this Pv, and remove Liens
	secrets, err := c.secretLister.List(labels.NewSelector())
	if err != nil {
		return err
	}

	resourceID := toPvResourceID(pvName)
	hasErr := false

	for _, secret := range secrets {
		err := c.deleteLiensForSecret(secret, resourceID)
		if err != nil {
			hasErr = true
		}
	}

	// There are errors in deleting Liens to any of the secrets, so return error to retry later.
	if hasErr {
		return fmt.Errorf("error deleting liens for secrets used by Pv %s", pvName)
	}

	return nil
}

// podAddedUpdated reacts to Pod events
func (c *Controller) podAddedUpdated(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("pod informer returned non-pod object: %#v", obj))
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for pod %#v: %v", pod, err))
		return
	}
	klog.V(4).InfoS("Got event on pod", key)

	c.podQueue.Add(key)
}

// podDeleted reacts to Pod deleted events
func (c *Controller) podDeleted(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("pod informer returned non-pod object: %#v", obj))
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for pod %#v: %v", pod, err))
		return
	}
	klog.V(4).InfoS("Got delete event on pod", key)

	c.podDeleteQueue.Add(key)
}

// pvDeleted reacts to PV delete events
func (c *Controller) pvDeleted(obj interface{}) {
	pv, ok := obj.(*v1.PersistentVolume)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("pv informer returned non-pv object: %#v", obj))
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(pv)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for pv %#v: %v", pv, err))
		return
	}
	klog.V(4).InfoS("Got delete event on pv", key)

	c.pvDeleteQueue.Add(key)
}

// pvAddedUpdated reacts to PV events
func (c *Controller) pvAddedUpdated(obj interface{}) {
	pv, ok := obj.(*v1.PersistentVolume)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("pv informer returned non-pv object: %#v", obj))
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(pv)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for pv %#v: %v", pv, err))
		return
	}
	klog.V(4).InfoS("Got event on pv", key)

	c.pvQueue.Add(key)
}

func (c *Controller) getSecretsUsedByPV(pv *v1.PersistentVolume) []string {
	secretKeys := []string{}

	switch {
	case pv.Spec.PersistentVolumeSource.CSI != nil:
		csi := pv.Spec.PersistentVolumeSource.CSI

		if csi.ControllerPublishSecretRef != nil {
			secretKeys = append(secretKeys, fmt.Sprintf("%s/%s",
				csi.ControllerPublishSecretRef.Namespace, csi.ControllerPublishSecretRef.Name))
		}

		if csi.NodeStageSecretRef != nil {
			secretKeys = append(secretKeys, fmt.Sprintf("%s/%s",
				csi.NodeStageSecretRef.Namespace, csi.NodeStageSecretRef.Name))
		}

		if csi.NodePublishSecretRef != nil {
			secretKeys = append(secretKeys, fmt.Sprintf("%s/%s",
				csi.NodePublishSecretRef.Namespace, csi.NodePublishSecretRef.Name))
		}

		if csi.ControllerExpandSecretRef != nil {
			secretKeys = append(secretKeys, fmt.Sprintf("%s/%s",
				csi.ControllerExpandSecretRef.Namespace, csi.ControllerExpandSecretRef.Name))
		}

		// Handle provisioner secret, whose reference is not directly stored in PV
		if pv.Spec.StorageClassName != "" {
			secretKey, err := c.getProvisionerSecretKey(pv)
			if err != nil {
				// TODO: PVC would already be deleted when PV is deleted,
				// so we will miss a chance to queue the secret to remove finalizer.
				// Current workaround is to queue all the secrets on PVC deletion.
				klog.Error(err)
			} else {
				secretKeys = append(secretKeys, secretKey)
			}
		}
	}

	return secretKeys
}

func (c *Controller) getProvisionerSecretKey(pv *v1.PersistentVolume) (string, error) {
	var sc *storagev1.StorageClass
	var pvc *v1.PersistentVolumeClaim
	var err error

	// No StorageClass name is defined
	if pv.Spec.StorageClassName == "" {
		return "", nil
	}
	// Get StorageClass for the PV
	sc, err = c.scLister.Get(pv.Spec.StorageClassName)
	if err != nil {
		return "", err
	}

	// Get the template for provisioner secret from StorageClass parameters
	nsTempl, nameTempl, err := getProvisionerSecretTemplate(sc.Parameters)
	if err != nil {
		return "", err
	}
	// No valid secret is defined in StorageClass
	if nsTempl == "" || nameTempl == "" {
		return "", nil
	}

	if requirePVC(nsTempl) || requirePVC(nameTempl) {
		if pv.Spec.ClaimRef == nil {
			return "", fmt.Errorf("template %q or %q requires information on PVC, but reference to PVC from the PV %q is empty: %v", nsTempl, nameTempl, pv.Name, pv)
		}

		// Get PVC
		pvc, err = c.pvcLister.PersistentVolumeClaims(pv.Spec.ClaimRef.Namespace).Get(pv.Spec.ClaimRef.Name)
		if err != nil {
			return "", err
		}
	}

	// Resolve namespace for provisioner secret
	ns, err := c.resolveNamespaceTemplate(nsTempl, pv, pvc)
	if err != nil {
		return "", err
	}
	// Resolve name for provisioner secret
	name, err := c.resolveNameTemplate(nameTempl, pv, pvc)
	if err != nil {
		return "", err
	}

	if ns == "" || name == "" {
		return "", fmt.Errorf("namespace %s or name %s is empty for provisioner secret for PV %s, StorageClass: %v", ns, name, pv.Name, sc)
	}

	return fmt.Sprintf("%s/%s", ns, name), nil
}

func (c *Controller) resolveNamespaceTemplate(template string, pv *v1.PersistentVolume, pvc *v1.PersistentVolumeClaim) (string, error) {
	return c.resolveTemplate(template, pv, pvc, false /* isName */)
}

func (c *Controller) resolveNameTemplate(template string, pv *v1.PersistentVolume, pvc *v1.PersistentVolumeClaim) (string, error) {
	return c.resolveTemplate(template, pv, pvc, true /* isName */)
}

func (c *Controller) resolveTemplate(template string, pv *v1.PersistentVolume, pvc *v1.PersistentVolumeClaim, isName bool) (string, error) {
	params := map[string]string{tokenPVNameKey: pv.Name}
	if requirePVC(template) {
		if pvc == nil {
			return "", fmt.Errorf("template %q requires pvc, but pvc is nil", template)
		}
		// Add params
		params[tokenPVCNamespaceKey] = pvc.Namespace
		if isName {
			// Add params only for name
			params[tokenPVCNameKey] = pvc.Name
			// TODO: need to confirm that annotation is supported for provisioner
			// as implemented in https://github.com/kubernetes-csi/external-provisioner/blob/213cd3d4e56fb439b06922ecf85d230a99d4e70d/pkg/controller/controller.go#L1596
			// but doens't seem to be mentioned in https://kubernetes-csi.github.io/docs/secrets-and-credentials-storage-class.html#createdelete-volume-secret
		}
	}

	missingParams := sets.NewString()
	resolved := os.Expand(template, func(k string) string {
		v, ok := params[k]
		if !ok {
			missingParams.Insert(k)
		}
		return v
	})
	if missingParams.Len() > 0 {
		return "", fmt.Errorf("invalid tokens: %q", missingParams.List())
	}
	if len(validation.IsDNS1123Subdomain(resolved)) > 0 {
		return "", fmt.Errorf("%q is resolved to %q, but is not a valid dns name", template, resolved)
	}
	return resolved, nil
}

func requirePVC(template string) bool {
	return strings.Contains(template, "${pvc.")
}

func getProvisionerSecretTemplate(scParams map[string]string) (string, string, error) {
	var nsTempl, nameTempl string
	var nsOK, nameOK bool

	if nsTempl, nsOK = scParams[provisionerSecretNamespaceKey]; !nsOK {
		nsTempl, nsOK = scParams[deprecatedProvisionerSecretNamespaceKey]
	}

	if nameTempl, nameOK = scParams[provisionerSecretNameKey]; !nameOK {
		nameTempl, nameOK = scParams[deprecatedProvisionerSecretNameKey]
	}

	if nsOK != nameOK {
		return "", "", fmt.Errorf("only namespace or name is found for provisioner secret, namespace %q, name %q: %v", nsTempl, nameTempl, scParams)
	} else if !nsOK && !nameOK {
		// Not defined in parameters
		return "", "", nil
	}

	return nsTempl, nameTempl, nil
}

func (c *Controller) updateLiensForSecret(secret *v1.Secret, resourceID string) error {
	klog.Errorf("updateLiensForSecret: secret %s/%s: %s", secret.Namespace, secret.Name, resourceID)

	patch, err := genLiensPatch(secret, resourceID)
	if err != nil {
		return err
	}

	// Already up to date
	if patch == nil {
		return nil
	}

	return patchSecretMetadata(c.metadataClient, secret, patch, types.MergePatchType)
}

func (c *Controller) deleteLiensForSecret(secret *v1.Secret, resourceID string) error {
	klog.Errorf("deleteLiensForSecret: secret %s/%s: %s", secret.Namespace, secret.Name, resourceID)

	patch, err := genDeleteLiensPatch(secret, resourceID)
	if err != nil {
		return err
	}

	// Already up to date
	if patch == nil {
		return nil
	}

	return patchSecretMetadata(c.metadataClient, secret, patch, types.MergePatchType)
}

func patchSecretMetadata(metadataClient metadata.Interface, secret *v1.Secret, patch []byte, pt types.PatchType) error {
	resource := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	_, err := metadataClient.Resource(resource).Namespace(secret.Namespace).Patch(context.TODO(), secret.Name, pt, patch, metav1.PatchOptions{})

	return err
}

func genLiensPatch(obj runtime.Object, resourceID string) ([]byte, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}

	newLiens := accessor.GetLiens()
	for _, lien := range newLiens {
		if lien == resourceID {
			// resourceID already exist.
			return nil, nil
		}
	}
	newLiens = append(newLiens, resourceID)

	return json.Marshal(&objectForLiensPatch{
		ObjectMetaForLiensPatch: ObjectMetaForLiensPatch{
			ResourceVersion: accessor.GetResourceVersion(),
			Liens:           newLiens,
		},
	})
}

func genDeleteLiensPatch(obj runtime.Object, resourceID string) ([]byte, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}

	shouldDelete := false
	newLiens := []string{}
	for _, lien := range accessor.GetLiens() {
		if lien == resourceID {
			shouldDelete = true
			continue
		}
		newLiens = append(newLiens, lien)
	}

	if !shouldDelete {
		return nil, nil
	}

	return json.Marshal(&objectForLiensPatch{
		ObjectMetaForLiensPatch: ObjectMetaForLiensPatch{
			ResourceVersion: accessor.GetResourceVersion(),
			Liens:           newLiens,
		},
	})
}

type objectForLiensPatch struct {
	ObjectMetaForLiensPatch `json:"metadata"`
}

type ObjectMetaForLiensPatch struct {
	ResourceVersion string   `json:"resourceVersion"`
	Liens           []string `json:"liens"`
}

func toPodResourceID(podNamespace, podName string) string {
	return fmt.Sprintf("%s v1/Pod/%s/%s", SecretProtectionLienID, podNamespace, podName)
}

func toPvResourceID(pvName string) string {
	return fmt.Sprintf("%s v1/PersistentVolume//%s", SecretProtectionLienID, pvName)
}
