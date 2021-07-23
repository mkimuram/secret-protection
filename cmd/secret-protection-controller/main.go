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

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/mkimuram/secret-protection/pkg/secretprotection"
	coreinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

const (
	// Default timeout
	defaultTimeout = time.Minute
)

// Command line flags
var (
	kubeconfig     = flag.String("kubeconfig", "", "Absolute path to the kubeconfig file. Required only when running out of cluster.")
	timeout        = flag.Duration("timeout", defaultTimeout, "The timeout for the controller. Default is 1 minute.")
	resyncPeriod   = flag.Duration("resync-period", 15*time.Minute, "Resync interval of the controller. Default is 15 minutes")
	enablePvcEvent = flag.Bool("enable-pvc-event", true, "Enables protection on pvc event.")
)

func main() {
	klog.InitFlags(nil)
	flag.Set("logtostderr", "true")
	flag.Parse()

	// Create the client config. Use kubeconfig if given, otherwise assume in-cluster.
	config, err := buildConfig(*kubeconfig)
	if err != nil {
		klog.Error(err.Error())
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Error(err.Error())
		os.Exit(1)
	}

	metadataClient, err := metadata.NewForConfig(config)
	if err != nil {
		klog.Error(err.Error())
		os.Exit(1)
	}

	// Pass a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	coreFactory := coreinformers.NewSharedInformerFactory(kubeClient, *resyncPeriod)

	stopCh := make(chan struct{})

	if err := startSecretProtectionController(ctx, coreFactory, kubeClient, metadataClient, *enablePvcEvent, stopCh); err != nil {
		klog.Error(err.Error())
		os.Exit(1)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	close(stopCh)
}

func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func startSecretProtectionController(ctx context.Context, coreFactory coreinformers.SharedInformerFactory, kubeClient kubernetes.Interface, metadataClient metadata.Interface, enablePvcEvent bool, stopCh <-chan struct{}) error {
	go secretprotection.NewSecretProtectionController(
		coreFactory.Core().V1().Secrets(),
		coreFactory.Core().V1().Pods(),
		coreFactory.Core().V1().PersistentVolumes(),
		coreFactory.Core().V1().PersistentVolumeClaims(),
		coreFactory.Storage().V1().StorageClasses(),
		kubeClient,
		metadataClient,
		enablePvcEvent,
	).Run(1, stopCh)
	coreFactory.Start(stopCh)

	return nil
}
