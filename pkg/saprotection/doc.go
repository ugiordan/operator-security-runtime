// Package saprotection provides a ValidatingWebhook that prevents unauthorized
// use of protected operator ServiceAccounts in pod specs.
//
// The webhook enforces strict creator identity checks: only the operator's own
// ServiceAccount is allowed to create pods that reference it. All other entities,
// including cluster admins, are blocked (defense-in-depth).
//
// Usage:
//
//	identities := []saprotection.ProtectedIdentity{
//	    {
//	        Namespace:          "my-operator-system",
//	        ServiceAccountName: "my-operator-controller-manager",
//	    },
//	}
//	if err := saprotection.SetupPodWebhookWithManager(mgr, identities); err != nil { ... }
package saprotection
