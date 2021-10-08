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

	"github.com/mkimuram/secret-protection/pkg/secretprotection/util/graph"
	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// SecretProtectionLienID is the name of lien on secrets that are consumed by the other resources
	SecretProtectionLienID = "kubernetes.io/secret-protection"
	// EnableProtectionAnnotation is the name of annotation on secrets that needs lien to be added
	EnableProtectionAnnotation = "kubernetes.io/enable-secret-protection"
	// ProtectionEnable is the annotation key that enables protection
	ProtectionEnable = "yes"

	deprecatedProvisionerSecretNameKey      = "provisioner-secret-name"
	deprecatedProvisionerSecretNamespaceKey = "provisioner-secret-namespace"
	provisionerSecretNameKey                = "csi.storage.k8s.io/provisioner-secret-name"
	provisionerSecretNamespaceKey           = "csi.storage.k8s.io/provisioner-secret-namespace"

	tokenPVNameKey       = "pv.name"
	tokenPVCNameKey      = "pvc.name"
	tokenPVCNamespaceKey = "pvc.namespace"

	createEvent = "create"
	updateEvent = "update"
	deleteEvent = "delete"

	podResource    = "pod"
	pvResource     = "pv"
	secretResource = "secret"
)

// Controller is controller that removes SecretProtectionFinalizer
// from secrets that are used by no other resources.
type Controller struct {
	client         clientset.Interface
	metadataClient metadata.Interface

	resources *graph.NodeMap

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

	graphQueue      workqueue.RateLimitingInterface
	addLienQueue    workqueue.RateLimitingInterface
	deleteLienQueue workqueue.RateLimitingInterface

	// allows overriding of StorageObjectInUseProtection feature Enabled/Disabled for testing
	storageObjectInUseProtectionEnabled bool
}

// NewSecretProtectionController returns a new instance of SecretProtectionController.
func NewSecretProtectionController(secretInformer coreinformers.SecretInformer, podInformer coreinformers.PodInformer, pvInformer coreinformers.PersistentVolumeInformer, pvcInformer coreinformers.PersistentVolumeClaimInformer, scInformer storageinformers.StorageClassInformer, cl clientset.Interface, metadataCl metadata.Interface, storageObjectInUseProtectionFeatureEnabled bool) *Controller {
	e := &Controller{
		client:                              cl,
		metadataClient:                      metadataCl,
		resources:                           graph.NewNodeMap(),
		graphQueue:                          workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_graph"),
		addLienQueue:                        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_add_lien"),
		deleteLienQueue:                     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "secretprotection_delete_lien"),
		storageObjectInUseProtectionEnabled: storageObjectInUseProtectionFeatureEnabled,
	}
	if cl != nil && cl.CoreV1().RESTClient().GetRateLimiter() != nil {
		ratelimiter.RegisterMetricAndTrackRateLimiterUsage("secret_protection_controller", cl.CoreV1().RESTClient().GetRateLimiter())
	}

	e.secretLister = secretInformer.Lister()
	e.secretListerSynced = secretInformer.Informer().HasSynced
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.handlerFunc(createEvent, secretResource, obj)
		},
		UpdateFunc: func(old, new interface{}) {
			e.handlerFunc(updateEvent, secretResource, new)
		},
	})

	e.podLister = podInformer.Lister()
	e.podListerSynced = podInformer.Informer().HasSynced
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.handlerFunc(createEvent, podResource, obj)
		},
		UpdateFunc: func(old, new interface{}) {
			e.handlerFunc(updateEvent, podResource, new)
		},
		DeleteFunc: func(obj interface{}) {
			e.handlerFunc(deleteEvent, podResource, obj)
		},
	})

	e.pvLister = pvInformer.Lister()
	e.pvListerSynced = pvInformer.Informer().HasSynced
	pvInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.handlerFunc(createEvent, pvResource, obj)
		},
		UpdateFunc: func(old, new interface{}) {
			e.handlerFunc(updateEvent, pvResource, new)
		},
		DeleteFunc: func(obj interface{}) {
			e.handlerFunc(deleteEvent, pvResource, obj)
		},
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
	defer c.graphQueue.ShutDown()
	defer c.addLienQueue.ShutDown()
	defer c.deleteLienQueue.ShutDown()

	klog.InfoS("Starting secret protection controller")
	defer klog.InfoS("Shutting down secret protection controller")

	if !cache.WaitForNamedCacheSync("secret protection", stopCh, c.secretListerSynced, c.podListerSynced, c.pvcListerSynced, c.scListerSynced) {
		return
	}

	// GraphWorker should be singleton
	go wait.Until(c.runGraphWorker, time.Second, stopCh)

	for i := 0; i < workers; i++ {
		go wait.Until(c.runAddLienWorker, time.Second, stopCh)
		go wait.Until(c.runDeleteLienWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) runGraphWorker() {
	for c.processNextGraphWorkItem() {
	}
}

// processNextGraphWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextGraphWorkItem() bool {
	key, quit := c.graphQueue.Get()
	if quit {
		return false
	}
	defer c.graphQueue.Done(key)

	operation, resourceType, namespace, name, err := splitHandlerKey(key.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error parsing key %q: %v", key, err))
		return true
	}

	err = c.processGraph(operation, resourceType, namespace, name)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("key %v failed with : %v", key, err))
		c.graphQueue.AddRateLimited(key)
		return true
	}

	c.graphQueue.Forget(key)
	return true
}

func (c *Controller) processGraph(operation, resourceType, namespace, name string) error {
	klog.V(4).InfoS("Processing graph", resourceType, klog.KRef(namespace, name))
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished processing graph", resourceType, klog.KRef(namespace, name), "duration", time.Since(startTime))
	}()

	switch operation {
	case createEvent, updateEvent:
		switch resourceType {
		case podResource:
			return c.processPodCreateUpdate(namespace, name)
		case pvResource:
			return c.processPvCreateUpdate(name)
		case secretResource:
			return c.processSecretCreateUpdate(namespace, name)
		default:
			klog.V(4).InfoS("Unknown resourceType specified, ignoring", "resourceType", resourceType)
			return nil
		}
	case deleteEvent:
		switch resourceType {
		case podResource, pvResource, secretResource:
			return c.processDelete(resourceType, namespace, name)
		default:
			klog.V(4).InfoS("Unknown resourceType specified, ignoring", "resourceType", resourceType)
			return nil
		}
	default:
		klog.V(4).InfoS("Unknown operation specified, ignoring", "operation", operation)
		return nil
	}

	return nil
}

func (c *Controller) processPodCreateUpdate(namespace, name string) error {
	pod, err := c.podLister.Pods(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		klog.V(4).InfoS("Pod not found, ignoring", "pod", klog.KRef(namespace, name))
		return nil
	}
	if err != nil {
		return err
	}

	podKey := graph.NewObjectKey(podResource, namespace, name)
	c.resources.EnsureNode(podKey)

	usedSecrets := map[graph.ObjectKey]bool{}
	// Find secrets used by this Pod
	for _, volume := range pod.Spec.Volumes {
		switch {
		case volume.Secret != nil:
			key := graph.NewObjectKey(secretResource, namespace, volume.Secret.SecretName)
			usedSecrets[key] = true
			c.resources.EnsureNode(key)
		}
	}

	// Compare with existing graph and update changes if needed
	deleted, added := c.resources.DiffTo(podKey, usedSecrets)

	// No changes with this update
	if len(deleted) == 0 && len(added) == 0 {
		return nil
	}

	// Delete deleted edges
	for key := range deleted {
		c.resources.DeleteEdge(podKey, key)
		if c.resources.GetNodeFromCount(key) == 0 {
			// delete lien
			c.deleteLienQueue.Add(key)
		}
	}

	// Add added edges
	for key := range added {
		c.resources.AddEdge(podKey, key)
		if c.resources.GetNodeFromCount(key) > 0 {
			// add lien
			c.addLienQueue.Add(key)
		}
	}

	return nil
}

func (c *Controller) processPvCreateUpdate(name string) error {
	pv, err := c.pvLister.Get(name)
	if apierrors.IsNotFound(err) {
		klog.V(4).InfoS("PV not found, ignoring", "pv", klog.KRef("", name))
		return nil
	}
	if err != nil {
		return err
	}

	pvKey := graph.NewObjectKey(pvResource, "", name)
	c.resources.EnsureNode(pvKey)

	usedSecrets := map[graph.ObjectKey]bool{}
	// Find secrets used by this PV
	for _, key := range c.getSecretsUsedByPV(pv) {
		usedSecrets[key] = true
	}

	// Compare with existing graph and update changes if needed
	deleted, added := c.resources.DiffTo(pvKey, usedSecrets)

	// No changes with this update
	if len(deleted) == 0 && len(added) == 0 {
		return nil
	}

	// Delete deleted edges
	for key := range deleted {
		c.resources.DeleteEdge(pvKey, key)
		if c.resources.GetNodeFromCount(key) == 0 {
			// delete lien
			c.deleteLienQueue.Add(key)
		}
	}

	// Add added edges
	for key := range added {
		c.resources.AddEdge(pvKey, key)
		if c.resources.GetNodeFromCount(key) > 0 {
			// add lien
			c.addLienQueue.Add(key)
		}
	}

	return nil
}

func checkSecretMeta(secret *v1.Secret) (bool, bool, error) {
	accessor, err := meta.Accessor(secret)
	if err != nil {
		return false, false, err
	}

	hasAnnon := false
	for key, val := range accessor.GetAnnotations() {
		if key == EnableProtectionAnnotation && val == ProtectionEnable {
			hasAnnon = true
		}
	}

	hasLien := false
	for _, lien := range accessor.GetLiens() {
		if lien == SecretProtectionLienID {
			hasLien = true
		}
	}

	return hasAnnon, hasLien, nil
}

func (c *Controller) processSecretCreateUpdate(namespace, name string) error {
	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		klog.V(4).InfoS("Secret not found, ignoring", "secret", klog.KRef(namespace, name))
		return nil
	}
	if err != nil {
		return err
	}

	secretKey := graph.NewObjectKey(secretResource, namespace, name)

	// Update liens if needed
	hasAnnon, hasLien, err := checkSecretMeta(secret)
	if err != nil {
		return err
	}

	if hasAnnon {
		// annotation but doesn't have lien and has references
		if !hasLien && c.resources.GetNodeFromCount(secretKey) > 0 {
			// add lien
			c.addLienQueue.Add(secretKey)
		}
	} else {
		// no annotation but has lien
		if hasLien {
			c.deleteLienQueue.Add(secretKey)
		}
	}

	return nil
}

func (c *Controller) processDelete(resourceType, namespace, name string) error {
	resourceKey := graph.NewObjectKey(resourceType, namespace, name)

	// Compare with existing graph and empty key
	deleted, _ := c.resources.DiffTo(resourceKey, map[graph.ObjectKey]bool{})

	// Delete deleted edges
	for key := range deleted {
		c.resources.DeleteEdge(resourceKey, key)
		if c.resources.GetNodeFromCount(key) == 0 {
			// delete lien
			c.deleteLienQueue.Add(key)
		}
	}

	return c.resources.DeleteNodeWithoutEdge(resourceKey)
}

func (c *Controller) runAddLienWorker() {
	for c.processNextAddLienWorkItem() {
	}
}

// processNextAddLienWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextAddLienWorkItem() bool {
	key, quit := c.addLienQueue.Get()
	if quit {
		return false
	}
	defer c.addLienQueue.Done(key)

	objKey, ok := key.(graph.ObjectKey)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("error parsing key %q", key))
		return true
	}

	if objKey.ResourceType != secretResource {
		utilruntime.HandleError(fmt.Errorf("invalid resource type %q", objKey.ResourceType))
		return true
	}

	secret, err := c.secretLister.Secrets(objKey.Namespace).Get(objKey.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("secret %v not found", key))
		}
		c.addLienQueue.AddRateLimited(key)
		return true
	}

	// Update liens if needed
	hasAnnon, hasLien, err := checkSecretMeta(secret)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to check metadata for %q: %v", objKey.ResourceType, err))
		c.addLienQueue.AddRateLimited(key)
		return true
	}

	if hasAnnon && !hasLien {
		err := c.addLiensForSecret(secret)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("secret %v failed with : %v", key, err))
			c.addLienQueue.AddRateLimited(key)
			return true
		}
	}

	c.addLienQueue.Forget(key)
	return true
}

func (c *Controller) runDeleteLienWorker() {
	for c.processNextDeleteLienWorkItem() {
	}
}

// processNextDeleteLienWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextDeleteLienWorkItem() bool {
	key, quit := c.deleteLienQueue.Get()
	if quit {
		return false
	}
	defer c.deleteLienQueue.Done(key)

	objKey, ok := key.(graph.ObjectKey)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("error parsing key %q", key))
		return true
	}

	if objKey.ResourceType != secretResource {
		utilruntime.HandleError(fmt.Errorf("invalid resource type %q", objKey.ResourceType))
		return true
	}

	secret, err := c.secretLister.Secrets(objKey.Namespace).Get(objKey.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("secret %v not found", key))
			return true
		}

		utilruntime.HandleError(fmt.Errorf("error getting secret %q: %v", key, err))
		c.deleteLienQueue.AddRateLimited(key)
		return true
	}

	hasAnnon, hasLien, err := checkSecretMeta(secret)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to check metadata for %q: %v", objKey.ResourceType, err))
		c.addLienQueue.AddRateLimited(key)
		return true
	}

	if hasLien {
		if hasAnnon {
			// TODO: Check if secret is actually not used by any resources

		}

		err := c.deleteLiensForSecret(secret)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("secret %v failed with : %v", key, err))
			c.deleteLienQueue.AddRateLimited(key)
			return true
		}
	}

	c.deleteLienQueue.Forget(key)
	return true
}

func toHandlerKey(operation, resourceType, namesapce, name string) string {
	return fmt.Sprintf("%s/%s/%s/%s", operation, resourceType, namesapce, name)
}

func splitHandlerKey(key string) (string, string, string, string, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		return "", "", "", "", fmt.Errorf("unexpected key format: %q", key)
	}

	return parts[0], parts[1], parts[2], parts[3], nil
}

// handlerFunc reacts to events
func (c *Controller) handlerFunc(operation, resourceType string, obj interface{}) {
	acc, err := meta.Accessor(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("informer returned object that can't access via accessor: %#v", obj))
		return
	}

	klog.V(4).InfoS("Got %s event on %s %s/%s", operation, resourceType, acc.GetNamespace(), acc.GetName())
	key := toHandlerKey(operation, resourceType, acc.GetNamespace(), acc.GetName())

	c.graphQueue.Add(key)
}

func (c *Controller) getSecretsUsedByPV(pv *v1.PersistentVolume) []graph.ObjectKey {
	secretKeys := []graph.ObjectKey{}

	switch {
	case pv.Spec.PersistentVolumeSource.CSI != nil:
		csi := pv.Spec.PersistentVolumeSource.CSI

		if csi.ControllerPublishSecretRef != nil {
			secretKeys = append(secretKeys, graph.NewObjectKey(secretResource,
				csi.ControllerPublishSecretRef.Namespace, csi.ControllerPublishSecretRef.Name))
		}

		if csi.NodeStageSecretRef != nil {
			secretKeys = append(secretKeys, graph.NewObjectKey(secretResource,
				csi.NodeStageSecretRef.Namespace, csi.NodeStageSecretRef.Name))
		}

		if csi.NodePublishSecretRef != nil {
			secretKeys = append(secretKeys, graph.NewObjectKey(secretResource,
				csi.NodePublishSecretRef.Namespace, csi.NodePublishSecretRef.Name))
		}

		if csi.ControllerExpandSecretRef != nil {
			secretKeys = append(secretKeys, graph.NewObjectKey(secretResource,
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
			} else if secretKey != nil {
				secretKeys = append(secretKeys, *secretKey)
			}
		}
	}

	return secretKeys
}

func (c *Controller) getProvisionerSecretKey(pv *v1.PersistentVolume) (*graph.ObjectKey, error) {
	var sc *storagev1.StorageClass
	var pvc *v1.PersistentVolumeClaim
	var err error

	// No StorageClass name is defined
	if pv.Spec.StorageClassName == "" {
		return nil, nil
	}
	// Get StorageClass for the PV
	sc, err = c.scLister.Get(pv.Spec.StorageClassName)
	if err != nil {
		return nil, err
	}

	// Get the template for provisioner secret from StorageClass parameters
	nsTempl, nameTempl, err := getProvisionerSecretTemplate(sc.Parameters)
	if err != nil {
		return nil, err
	}
	// No valid secret is defined in StorageClass
	if nsTempl == "" || nameTempl == "" {
		return nil, nil
	}

	if requirePVC(nsTempl) || requirePVC(nameTempl) {
		if pv.Spec.ClaimRef == nil {
			return nil, fmt.Errorf("template %q or %q requires information on PVC, but reference to PVC from the PV %q is empty: %v", nsTempl, nameTempl, pv.Name, pv)
		}

		// Get PVC
		pvc, err = c.pvcLister.PersistentVolumeClaims(pv.Spec.ClaimRef.Namespace).Get(pv.Spec.ClaimRef.Name)
		if err != nil {
			return nil, err
		}
	}

	// Resolve namespace for provisioner secret
	ns, err := c.resolveNamespaceTemplate(nsTempl, pv, pvc)
	if err != nil {
		return nil, err
	}
	// Resolve name for provisioner secret
	name, err := c.resolveNameTemplate(nameTempl, pv, pvc)
	if err != nil {
		return nil, err
	}

	if ns == "" || name == "" {
		return nil, fmt.Errorf("namespace %s or name %s is empty for provisioner secret for PV %s, StorageClass: %v", ns, name, pv.Name, sc)
	}

	key := graph.NewObjectKey(secretResource, ns, name)
	return &key, nil
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

func (c *Controller) addLiensForSecret(secret *v1.Secret) error {
	klog.Errorf("addLiensForSecret: secret %s/%s", secret.Namespace, secret.Name)

	patch, err := genLiensPatch(secret)
	if err != nil {
		return err
	}

	// Already up to date
	if patch == nil {
		return nil
	}

	return patchSecretMetadata(c.metadataClient, secret, patch, types.MergePatchType)
}

func (c *Controller) deleteLiensForSecret(secret *v1.Secret) error {
	klog.Errorf("deleteLiensForSecret: secret %s/%s", secret.Namespace, secret.Name)

	patch, err := genDeleteLiensPatch(secret)
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

func genLiensPatch(obj runtime.Object) ([]byte, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}

	newLiens := accessor.GetLiens()
	for _, lien := range newLiens {
		if lien == SecretProtectionLienID {
			// resourceID already exist.
			return nil, nil
		}
	}
	newLiens = append(newLiens, SecretProtectionLienID)

	return json.Marshal(&objectForLiensPatch{
		ObjectMetaForLiensPatch: ObjectMetaForLiensPatch{
			ResourceVersion: accessor.GetResourceVersion(),
			Liens:           newLiens,
		},
	})
}

func genDeleteLiensPatch(obj runtime.Object) ([]byte, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}

	shouldDelete := false
	newLiens := []string{}
	for _, lien := range accessor.GetLiens() {
		if lien == SecretProtectionLienID {
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

// ObjectMetaForLiensPatch represents ObjectMeta for Liens patch
type ObjectMetaForLiensPatch struct {
	ResourceVersion string   `json:"resourceVersion"`
	Liens           []string `json:"liens"`
}
