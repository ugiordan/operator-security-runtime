package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ExampleResourceSpec defines the desired state of ExampleResource.
type ExampleResourceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of ExampleResource. Edit exampleresource_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// ExampleResourceStatus defines the observed state of ExampleResource.
type ExampleResourceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ExampleResource is the Schema for the exampleresources API.
type ExampleResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExampleResourceSpec   `json:"spec,omitempty"`
	Status ExampleResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExampleResourceList contains a list of ExampleResource.
type ExampleResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExampleResource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ExampleResource{}, &ExampleResourceList{})
}
