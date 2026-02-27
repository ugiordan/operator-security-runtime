// Package impersonationguard provides a controller-runtime reconciler that
// hardens Kubernetes RBAC by stripping the `impersonate` verb from the
// `system:aggregate-to-edit` ClusterRole. By default, this ClusterRole grants
// `impersonate` on `serviceaccounts`, which aggregates into the `edit` and
// `admin` roles — allowing any namespace editor to impersonate any
// ServiceAccount in their namespace. This bypasses the SA protection webhook
// entirely because impersonation is processed at the Kubernetes authentication
// layer, before admission webhooks fire.
//
// The reconciler watches `system:aggregate-to-edit` and continuously ensures
// the `impersonate` verb is removed. It also sets the annotation
// `rbac.authorization.kubernetes.io/autoupdate: "false"` to prevent the
// Kubernetes RBAC controller from re-adding the verb on API server restart.
//
// Usage:
//
//	if err := (&impersonationguard.ImpersonationGuardReconciler{
//	    Client: mgr.GetClient(),
//	    Scheme: mgr.GetScheme(),
//	}).SetupWithManager(mgr); err != nil {
//	    setupLog.Error(err, "unable to create impersonation guard")
//	    os.Exit(1)
//	}
package impersonationguard
