package mockoidc

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a mock user that the server will grant Oauth tokens for.
// Calls to the `authorization_endpoint` will pop any mock Users added to the
// `UserQueue`. Otherwise `DefaultUser()` is returned.
type User interface {
	// Unique ID for the User. This will be the Subject claim
	ID() string

	// Userinfo returns the Userinfo JSON representation of a User with data
	// appropriate for the passed scope []string.
	Userinfo([]string) ([]byte, error)

	// Claims returns the ID Token Claims for a User with data appropriate for
	// the passed scope []string. It builds off the passed BaseIDTokenClaims.
	Claims([]string, *IDTokenClaims) (jwt.Claims, error)
}

// MockUser is a default implementation of the User interface
type MockUser struct {
	// openid scope
	Subject string

	// email scope
	Email         string
	EmailVerified bool

	// profile scope
	Name              string
	PreferredUsername string

	// phone scope
	Phone         string
	PhoneVerified bool

	// address scope
	Address string

	Groups []string
}

// DefaultUser returns a default MockUser that is set in
// `authorization_endpoint` if the UserQueue is empty.
func DefaultUser() *MockUser {
	return &MockUser{
		Subject:           "1234567890",
		Email:             "jane.doe@example.com",
		Name:              "Jane Doe",
		PreferredUsername: "jane.doe",
		Phone:             "555-987-6543",
		PhoneVerified:     true,
		Address:           "123 Main Street",
		Groups:            []string{"engineering", "design"},
		EmailVerified:     true,
	}
}

type mockUserinfo struct {
	Subject           string   `json:"sub,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	PhoneVerified     bool     `json:"phone_number_verified,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (u *MockUser) ID() string {
	return u.Subject
}

func (u *MockUser) Userinfo(scope []string) ([]byte, error) {
	user := u.scopedClone(scope)

	info := &mockUserinfo{
		Subject:           user.Subject,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Name:              user.Name,
		PreferredUsername: user.PreferredUsername,
		Phone:             user.Phone,
		PhoneVerified:     user.PhoneVerified,
		Address:           user.Address,
		Groups:            user.Groups,
	}

	return json.Marshal(info)
}

type mockClaims struct {
	*IDTokenClaims
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	PhoneVerified     bool     `json:"phone_number_verified,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (u *MockUser) Claims(scope []string, claims *IDTokenClaims) (jwt.Claims, error) {
	user := u.scopedClone(scope)

	return &mockClaims{
		IDTokenClaims:     claims,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Name:              user.Name,
		PreferredUsername: user.PreferredUsername,
		Phone:             user.Phone,
		PhoneVerified:     user.PhoneVerified,
		Address:           user.Address,
		Groups:            user.Groups,
	}, nil
}

func (u *MockUser) scopedClone(scopes []string) *MockUser {
	clone := &MockUser{
		Subject: u.Subject,
	}
	for _, scope := range scopes {
		switch scope {
		case "profile":
			clone.Name = u.Name
			clone.PreferredUsername = u.PreferredUsername
		case "address":
			clone.Address = u.Address
		case "phone":
			clone.Phone = u.Phone
			clone.PhoneVerified = u.PhoneVerified
		case "email":
			clone.Email = u.Email
			clone.EmailVerified = u.EmailVerified
		case "groups":
			clone.Groups = append(make([]string, 0, len(u.Groups)), u.Groups...)
		}
	}
	return clone
}
