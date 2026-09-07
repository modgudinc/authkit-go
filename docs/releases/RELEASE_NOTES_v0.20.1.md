# authkit-go v0.20.1

A small, additive release on top of the [v0.20.0](RELEASE_NOTES_v0.20.0.md) decoupled-identity model. It adds **guarded membership mutations** so a workspace can never be left without a member holding a required role (e.g. its last Admin).

```bash
go get github.com/modgudinc/authkit-go@v0.20.1
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## What's new

Two additions to `MembershipService`:

```go
RemoveGuarded(ctx, userID, tenantID, requireRole string) error
UpdateRolesGuarded(ctx, userID, tenantID string, roles []string, requireRole string) error
```

They behave exactly like `Remove` / `UpdateRoles`, with one extra rule: the change is **refused** when it would leave the tenant with **no active member holding `requireRole`**. On refusal nothing is written and the call returns the new sentinel `ErrLastRoleHolder` (map it to HTTP 409).

`requireRole` is an **opaque** role string named by the caller — authkit still never interprets roles. Pass the role you want to keep at least one active holder of (e.g. `"Admin"`); pass `""` to disable the guard and get the plain `Remove` / `UpdateRoles` behaviour.

```go
// Refuse to remove a workspace's last Admin.
err := kit.MembershipService().RemoveGuarded(ctx, userID, tenantID, "Admin")
if errors.Is(err, authkit.ErrLastRoleHolder) {
    http.Error(w, "cannot remove the last Admin", http.StatusConflict)
    return
}
```

## Why it's safe under concurrency

The guard is not a best-effort application check. Each guarded call runs the **check and the mutation in one transaction**, serialized per tenant by a **transaction-scoped advisory lock** (`pg_advisory_xact_lock`), and asserts the "≥1 active holder remains" invariant on the post-mutation state before committing.

That closes the check-and-act race that a list-then-mutate in application code cannot: two admins each removing the other's membership at the same moment — even from **different processes or replicas** — can no longer both succeed. One commits; the other observes the post-state, rolls back, and gets `ErrLastRoleHolder`. Exactly one active holder always survives.

## Compatibility

Purely additive — no schema migration, no changes to existing methods or their behaviour. Upgrading is a `go get`. (`MembershipService` is an interface authkit returns to callers; the new methods are available on the value from `kit.MembershipService()`.)
