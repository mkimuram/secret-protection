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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// isDeletionCandidate checks if object is candidate to be deleted
// Copied from kubernetes/pkg/controller/volume/protectionutil/utils.go
func isDeletionCandidate(obj metav1.Object, finalizer string) bool {
	return obj.GetDeletionTimestamp() != nil && containsString(obj.GetFinalizers(),
		finalizer, nil)
}

// needToAddFinalizer checks if need to add finalizer to object
// Copied from kubernetes/pkg/controller/volume/protectionutil/utils.go
func needToAddFinalizer(obj metav1.Object, finalizer string) bool {
	return obj.GetDeletionTimestamp() == nil && !containsString(obj.GetFinalizers(),
		finalizer, nil)
}

// containsString checks if a given slice of strings contains the provided string.
// If a modifier func is provided, it is called with the slice item before the comparation.
// Copied from kubernetes/pkg/util/slice/slice.go
func containsString(slice []string, s string, modifier func(s string) string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
		if modifier != nil && modifier(item) == s {
			return true
		}
	}
	return false
}

// removeString returns a newly created []string that contains all items from slice that
// are not equal to s and modifier(s) in case modifier func is provided.
// Copied from kubernetes/pkg/util/slice/slice.go
func removeString(slice []string, s string, modifier func(s string) string) []string {
	newSlice := make([]string, 0)
	for _, item := range slice {
		if item == s {
			continue
		}
		if modifier != nil && modifier(item) == s {
			continue
		}
		newSlice = append(newSlice, item)
	}
	if len(newSlice) == 0 {
		// Sanitize for unit tests so we don't need to distinguish empty array
		// and nil.
		newSlice = nil
	}
	return newSlice
}

// isPodTerminated checks if pod is terminated
// Copied from kubernetes/pkg/volume/util/util.go
func isPodTerminated(pod *v1.Pod, podStatus v1.PodStatus) bool {
	return podStatus.Phase == v1.PodFailed || podStatus.Phase == v1.PodSucceeded || (pod.DeletionTimestamp != nil && notRunning(podStatus.ContainerStatuses))
}

// notRunning returns true if every status is terminated or waiting, or the status list
// is empty.
// Copied from kubernetes/pkg/volume/util/util.go
func notRunning(statuses []v1.ContainerStatus) bool {
	for _, status := range statuses {
		if status.State.Terminated == nil && status.State.Waiting == nil {
			return false
		}
	}
	return true
}
