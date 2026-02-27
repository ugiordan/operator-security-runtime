package impersonationguard

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// TargetClusterRole is the name of the ClusterRole that grants
	// impersonate on serviceaccounts by default.
	TargetClusterRole = "system:aggregate-to-edit"

	// AutoUpdateAnnotation is the annotation used by the Kubernetes RBAC
	// controller to decide whether to reconcile a ClusterRole back to its
	// default state on API server restart.
	AutoUpdateAnnotation = "rbac.authorization.kubernetes.io/autoupdate"
)

// ImpersonationGuardReconciler watches the system:aggregate-to-edit ClusterRole
// and strips the impersonate verb from any rule targeting serviceaccounts.
type ImpersonationGuardReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile ensures the impersonate verb is removed from the
// system:aggregate-to-edit ClusterRole.
func (r *ImpersonationGuardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (reconcile.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithName("impersonation-guard")

	// Only process our target ClusterRole.
	if req.Name != TargetClusterRole {
		return reconcile.Result{}, nil
	}

	cr := &rbacv1.ClusterRole{}
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, cr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ClusterRole not found, nothing to do", "clusterRole", req.Name)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting ClusterRole %s: %w", req.Name, err)
	}

	stripped, modified := stripImpersonate(cr.Rules)
	if !modified {
		log.Info("ClusterRole already clean, no impersonate verb found", "clusterRole", req.Name)
		return reconcile.Result{}, nil
	}

	cr.Rules = stripped

	// Set autoupdate annotation to prevent the RBAC controller from
	// re-adding the impersonate verb on API server restart.
	if cr.Annotations == nil {
		cr.Annotations = make(map[string]string)
	}
	cr.Annotations[AutoUpdateAnnotation] = "false"

	if err := r.Update(ctx, cr); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating ClusterRole %s: %w", req.Name, err)
	}

	log.Info("stripped impersonate verb from ClusterRole", "clusterRole", req.Name)
	return reconcile.Result{}, nil
}

// SetupWithManager registers the reconciler with the manager, filtering to
// only watch the target ClusterRole.
func (r *ImpersonationGuardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1.ClusterRole{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return e.Object.GetName() == TargetClusterRole
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return e.ObjectNew.GetName() == TargetClusterRole
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return false
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return e.Object.GetName() == TargetClusterRole
			},
		}).
		Complete(r)
}

// stripImpersonate removes the "impersonate" verb from any rule targeting
// serviceaccounts. If a rule only has the "impersonate" verb, the entire rule
// is removed. Rules with wildcard verbs targeting serviceaccounts are also
// removed since we can't safely expand "*" minus impersonate.
// Returns the filtered rules and whether any modification was made.
func stripImpersonate(rules []rbacv1.PolicyRule) ([]rbacv1.PolicyRule, bool) {
	modified := false
	var result []rbacv1.PolicyRule

	for _, rule := range rules {
		if !targetsServiceAccounts(rule) {
			result = append(result, rule)
			continue
		}

		// Check for wildcard verb (grants everything including impersonate)
		if hasVerb(rule.Verbs, "*") {
			modified = true
			// Drop entire rule — can't safely expand "*" minus impersonate
			continue
		}

		cleaned := removeVerb(rule.Verbs, "impersonate")
		if len(cleaned) == len(rule.Verbs) {
			// No impersonate verb found in this rule.
			result = append(result, rule)
			continue
		}

		modified = true
		if len(cleaned) == 0 {
			// impersonate was the only verb -- drop the entire rule.
			continue
		}

		rule.Verbs = cleaned
		result = append(result, rule)
	}

	return result, modified
}

// targetsServiceAccounts returns true if the rule's Resources list contains
// "serviceaccounts" or "*" (wildcard).
func targetsServiceAccounts(rule rbacv1.PolicyRule) bool {
	for _, res := range rule.Resources {
		if res == "serviceaccounts" || res == "*" {
			return true
		}
	}
	return false
}

// removeVerb returns a copy of verbs with all occurrences of target removed.
func removeVerb(verbs []string, target string) []string {
	var result []string
	for _, v := range verbs {
		if v != target {
			result = append(result, v)
		}
	}
	return result
}

// hasVerb returns true if the verbs list contains the target verb.
func hasVerb(verbs []string, target string) bool {
	for _, v := range verbs {
		if v == target {
			return true
		}
	}
	return false
}
