/*
Copyright The Kubernetes Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package v1beta1

import (
	"context"
	"time"

	scheme "github.com/onosproject/onos-operator/pkg/clientset/versioned/scheme"
	v1beta1 "github.com/onosproject/onos-operator/pkg/apis/topo/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// KindsGetter has a method to return a KindInterface.
// A group's client should implement this interface.
type KindsGetter interface {
	Kinds(namespace string) KindInterface
}

// KindInterface has methods to work with Kind resources.
type KindInterface interface {
	Create(*v1beta1.Kind) (*v1beta1.Kind, error)
	Update(*v1beta1.Kind) (*v1beta1.Kind, error)
	UpdateStatus(*v1beta1.Kind) (*v1beta1.Kind, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1beta1.Kind, error)
	List(opts v1.ListOptions) (*v1beta1.KindList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1beta1.Kind, err error)
	KindExpansion
}

// kinds implements KindInterface
type kinds struct {
	client rest.Interface
	ns     string
}

// newKinds returns a Kinds
func newKinds(c *TopoV1beta1Client, namespace string) *kinds {
	return &kinds{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the kind, and returns the corresponding kind object, and an error if there is any.
func (c *kinds) Get(name string, options v1.GetOptions) (result *v1beta1.Kind, err error) {
	result = &v1beta1.Kind{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("kinds").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(context.TODO()).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Kinds that match those selectors.
func (c *kinds) List(opts v1.ListOptions) (result *v1beta1.KindList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1beta1.KindList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("kinds").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(context.TODO()).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested kinds.
func (c *kinds) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("kinds").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(context.TODO())
}

// Create takes the representation of a kind and creates it.  Returns the server's representation of the kind, and an error, if there is any.
func (c *kinds) Create(kind *v1beta1.Kind) (result *v1beta1.Kind, err error) {
	result = &v1beta1.Kind{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("kinds").
		Body(kind).
		Do(context.TODO()).
		Into(result)
	return
}

// Update takes the representation of a kind and updates it. Returns the server's representation of the kind, and an error, if there is any.
func (c *kinds) Update(kind *v1beta1.Kind) (result *v1beta1.Kind, err error) {
	result = &v1beta1.Kind{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("kinds").
		Name(kind.Name).
		Body(kind).
		Do(context.TODO()).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *kinds) UpdateStatus(kind *v1beta1.Kind) (result *v1beta1.Kind, err error) {
	result = &v1beta1.Kind{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("kinds").
		Name(kind.Name).
		SubResource("status").
		Body(kind).
		Do(context.TODO()).
		Into(result)
	return
}

// Delete takes name of the kind and deletes it. Returns an error if one occurs.
func (c *kinds) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("kinds").
		Name(name).
		Body(options).
		Do(context.TODO()).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *kinds) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("kinds").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do(context.TODO()).
		Error()
}

// Patch applies the patch and returns the patched kind.
func (c *kinds) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1beta1.Kind, err error) {
	result = &v1beta1.Kind{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("kinds").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do(context.TODO()).
		Into(result)
	return
}
