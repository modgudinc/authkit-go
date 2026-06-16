# Service Examples

These examples show typical service usage. They assume `identity` is an initialized `authkit.AuthKit` value and `ctx` is a request context.

## Tenants

```go
tenantService := identity.TenantService()

tenant, err := tenantService.CreateTenant(ctx, model.CreateTenantRequest{
	TenantID:       "acme.com",
	Name:           "Acme",
	AllowedDomains: []string{"acme.com"},
})
if err != nil {
	return err
}

if err := tenantService.ValidateDomainAccess(ctx, "admin@acme.com", tenant.TenantID); err != nil {
	return err
}
```

## Users And Passwords

```go
passwordService := identity.PasswordService()
userService := identity.UserService()

hash, err := passwordService.HashPassword("ValidPass1!")
if err != nil {
	return err
}

userID, err := userService.Create(ctx, model.CreateUserRequest{
	Email:        "admin@acme.com",
	PasswordHash: hash,
	TenantID:     "acme.com",
	DisplayName:  "Admin",
	Roles:        []string{"Admin"},
})
if err != nil {
	return err
}

_ = userID
```

## Login And JWT Validation

```go
authService := identity.AuthService()

login, err := authService.Login(ctx, model.LoginRequest{
	Email:    "admin@acme.com",
	Password: "ValidPass1!",
	TenantID: "acme.com",
	SessionInfo: &model.SessionInfo{
		IPAddress:  "203.0.113.10",
		UserAgent:  "example-client",
		DeviceName: "laptop",
	},
})
if err != nil {
	return err
}

claims, err := authService.ValidateJWT(ctx, login.AccessToken)
if err != nil {
	return err
}

_ = claims
```

## Refresh And Logout

```go
refreshed, err := authService.RefreshToken(ctx, model.RefreshRequest{
	RefreshToken: login.RefreshToken,
})
if err != nil {
	return err
}

if err := authService.Logout(ctx, refreshed.RefreshToken); err != nil {
	return err
}
```

## API Keys

```go
apiKeyService := identity.APIKeyService()
expiresIn := 90 * 24 * time.Hour

created, err := apiKeyService.CreateAPIKey(ctx, model.CreateAPIKeyRequest{
	TenantID:  "acme.com",
	CreatedBy: userID,
	Name:      "Production",
	ExpiresIn: &expiresIn,
})
if err != nil {
	return err
}

// Store or display created.APIKey once. It is never stored in plaintext.
keyContext, err := apiKeyService.ValidateAPIKey(ctx, created.APIKey)
if err != nil {
	return err
}

_ = keyContext
```

## Invitations

```go
invitationService := identity.InvitationService()

invitation, err := invitationService.CreateInvitation(ctx, model.CreateInvitationRequest{
	TenantID:  "acme.com",
	CreatedBy: userID,
	Email:     "invitee@acme.com",
	Roles:     []string{"Member"},
})
if err != nil {
	return err
}

// Redeem the invitation and create the user atomically (validate + consume +
// create in one transaction). Prefer this over ValidateInvitation + IncrementUseCount,
// which is non-atomic and can over-redeem a single-use invitation.
passwordHash, err := identity.PasswordService().HashPassword("SecurePass1!")
if err != nil {
	return err
}
newUserID, err := invitationService.AcceptInvitation(ctx, model.AcceptInvitationRequest{
	Code:         invitation.Code,
	Email:        "invitee@acme.com",
	DisplayName:  "Invited User",
	PasswordHash: passwordHash,
})
if err != nil {
	return err
}
_ = newUserID
```

## OTP

```go
otpService := identity.OTPService()

generated, err := otpService.Generate(ctx, model.OTPGenerateRequest{
	TenantID:           "acme.com",
	Email:              "user@acme.com",
	Purpose:            "signup",
	ExpirationDuration: time.Hour,
})
if err != nil {
	return err
}

// Send generated.Code through your email/SMS provider.
if err := otpService.Validate(ctx, model.OTPValidateRequest{
	TenantID: "acme.com",
	Email:    "user@acme.com",
	Code:     generated.Code,
	Purpose:  "signup",
}); err != nil {
	return err
}
```

## Secrets

```go
secretService := identity.SecretService()

saved, err := secretService.SaveSecret(ctx, model.SaveSecretRequest{
	TenantID:   "acme.com",
	Key:        "openai",
	PlainValue: "sk-live-secret", // placeholder — pass the real provider key here
	CreatedBy:  userID,
})
if err != nil {
	return err
}

plain, err := secretService.GetSecret(ctx, saved.TenantID, saved.Key)
if err != nil {
	return err
}

_ = plain
```
