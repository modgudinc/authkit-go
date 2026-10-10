// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package model holds the data types that cross authkit-go's public API — the
// domain entities returned to callers (User, Tenant, APIKey, Invitation, Secret,
// JWTClaims, UserStatusChange) and the request/response structs (including
// SessionInfo) used to call the services. The sentinel errors callers branch on
// with errors.Is also live here (see errors.go), re-exported from the root authkit
// package.
//
// API-stability contract:
//
//   - Exported struct fields are append-only within a minor (0.x) line: fields
//     may be added but are not renamed or removed except in a release flagged as
//     breaking. Construct these structs with keyed literals
//     (model.CreateUserRequest{Email: ...}) so that adding a field does not break
//     your build.
//
//   - Values RETURNED by the services (e.g. *User from GetByID, *Tenant from
//     TenantService.Get, *JWTClaims from ValidateJWT) are read-back snapshots. Treat them
//     as read-only: mutating a returned struct (for example flipping User.IsLocked
//     or editing User.TokenVersion / Membership.Roles) changes nothing server-side and
//     is not a supported way to perform an operation. Use the dedicated service
//     methods, which take request structs and IDs, to make changes.
//
//   - JWTClaims embeds a third-party type; see its doc comment for the resulting
//     golang-jwt/v5 SemVer coupling.
package model
