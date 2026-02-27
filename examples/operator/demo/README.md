# Dynamic RBAC Scoping Demo

## What This Demo Shows

- The operator's static ClusterRole contains **no secrets permissions** at all.
- When an `ExampleResource` CR is created in a namespace, a scoped `Role` and `RoleBinding` are **dynamically created** in that namespace, granting the operator secrets access only there.
- Each namespace is independently scoped -- deploying a CR in `project-a` does **not** grant access in `project-b`.
- When a CR is deleted, the scoped RBAC resources are **automatically cleaned up**, revoking secrets access in that namespace.
- Other namespaces with active CRs remain **unaffected** by cleanup in a different namespace.

## Prerequisites

- A running Kubernetes cluster (Kind recommended for local testing)
- The operator deployed into the cluster (`make deploy IMG=...`)
- `kubectl` configured to communicate with the cluster

## How to Run

```bash
# From the repository root
./demo/demo-rbac-scoping.sh
```

To override the operator name used in Role names (default: `example-operator`):

```bash
OPERATOR_NAME=my-operator ./demo/demo-rbac-scoping.sh
```

The script will clean up all demo resources automatically on exit.
