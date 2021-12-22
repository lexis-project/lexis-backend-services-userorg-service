// Code generated by go-swagger; DO NOT EDIT.

package user_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ListUsersURL generates an URL for the list users operation
type ListUsersURL struct {
	Email       *strfmt.Email
	Permissions *bool
	Project     *strfmt.UUID
	Scope       *string

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *ListUsersURL) WithBasePath(bp string) *ListUsersURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *ListUsersURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *ListUsersURL) Build() (*url.URL, error) {
	var _result url.URL

	var _path = "/user"

	_basePath := o._basePath
	if _basePath == "" {
		_basePath = "/api/v0.3"
	}
	_result.Path = golangswaggerpaths.Join(_basePath, _path)

	qs := make(url.Values)

	var emailQ string
	if o.Email != nil {
		emailQ = o.Email.String()
	}
	if emailQ != "" {
		qs.Set("email", emailQ)
	}

	var permissionsQ string
	if o.Permissions != nil {
		permissionsQ = swag.FormatBool(*o.Permissions)
	}
	if permissionsQ != "" {
		qs.Set("permissions", permissionsQ)
	}

	var projectQ string
	if o.Project != nil {
		projectQ = o.Project.String()
	}
	if projectQ != "" {
		qs.Set("project", projectQ)
	}

	var scopeQ string
	if o.Scope != nil {
		scopeQ = *o.Scope
	}
	if scopeQ != "" {
		qs.Set("scope", scopeQ)
	}

	_result.RawQuery = qs.Encode()

	return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *ListUsersURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *ListUsersURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *ListUsersURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on ListUsersURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on ListUsersURL")
	}

	base, err := o.Build()
	if err != nil {
		return nil, err
	}

	base.Scheme = scheme
	base.Host = host
	return base, nil
}

// StringFull returns the string representation of a complete url
func (o *ListUsersURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
