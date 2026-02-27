// Package rbacaudit provides startup RBAC audit functions that check for
// impersonation and token request exposure in the cluster's RBAC configuration.
//
// Call AuditImpersonationExposure during operator startup to detect known
// attack vectors and log warnings before the operator begins reconciliation.
//
// Usage:
//
//	findings := rbacaudit.AuditImpersonationExposure(ctx, mgr.GetAPIReader())
//	for _, f := range findings {
//	    setupLog.Info("RBAC audit finding",
//	        "severity", f.Severity,
//	        "category", f.Category,
//	        "resource", f.Resource,
//	        "description", f.Description)
//	}
package rbacaudit
