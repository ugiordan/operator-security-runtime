package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/opendatahub-io/operator-security-runtime/pkg/rbacscope"

	appv1alpha1 "github.com/opendatahub-io/operator-security-runtime/examples/operator/api/v1alpha1"
)

const finalizerName = "app.example.com/scoped-access-cleanup"

// ExampleResourceReconciler reconciles a ExampleResource object.
// It demonstrates dynamic RBAC scoping: when a CR exists in a namespace,
// the operator gets secrets access there. When deleted, access is revoked.
type ExampleResourceReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RBACScoper *rbacscope.RBACScoper
}

// +kubebuilder:rbac:groups=app.example.com,resources=exampleresources,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app.example.com,resources=exampleresources/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=app.example.com,resources=exampleresources/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,resourceNames=system:aggregate-to-edit,verbs=get;list;watch;update;patch
//
// NOTE: No kubebuilder:rbac marker for secrets is intentional. Secrets access
// is provided dynamically by the RBACScoper via namespace-scoped Roles, not
// through the static ClusterRole.

func (r *ExampleResourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the ExampleResource
	cr := &appv1alpha1.ExampleResource{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion: clean up RBAC and remove finalizer
	if !cr.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(cr, finalizerName) {
			log.Info("cleaning up scoped access", "namespace", cr.Namespace)
			if err := r.RBACScoper.CleanupAccess(ctx, cr); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup scoped access: %w", err)
			}

			controllerutil.RemoveFinalizer(cr, finalizerName)
			if err := r.Update(ctx, cr); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(cr, finalizerName) {
		controllerutil.AddFinalizer(cr, finalizerName)
		if err := r.Update(ctx, cr); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Step 1: Ensure scoped access in this namespace
	log.Info("ensuring scoped access", "namespace", cr.Namespace)
	if err := r.RBACScoper.EnsureAccess(ctx, cr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to ensure scoped access: %w", err)
	}

	// Step 2: Now the operator can read secrets in this namespace.
	// This simulates what DSPO/Feast/Notebooks do during reconciliation.
	log.Info("secrets access available, proceeding with reconciliation",
		"namespace", cr.Namespace,
		"cr", cr.Name)

	// Example: list secrets in this namespace to demonstrate access works
	secretList := &corev1.SecretList{}
	if err := r.List(ctx, secretList, client.InNamespace(cr.Namespace)); err != nil {
		log.Error(err, "failed to list secrets - RBAC may not have propagated yet, requeuing")
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	log.Info("successfully listed secrets", "namespace", cr.Namespace, "count", len(secretList.Items))

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ExampleResourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appv1alpha1.ExampleResource{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Named("exampleresource").
		Complete(r)
}
