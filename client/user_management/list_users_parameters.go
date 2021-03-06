// Code generated by go-swagger; DO NOT EDIT.

package user_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewListUsersParams creates a new ListUsersParams object
// with the default values initialized.
func NewListUsersParams() *ListUsersParams {
	var (
		scopeDefault = string("OWN")
	)
	return &ListUsersParams{
		Scope: &scopeDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewListUsersParamsWithTimeout creates a new ListUsersParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListUsersParamsWithTimeout(timeout time.Duration) *ListUsersParams {
	var (
		scopeDefault = string("OWN")
	)
	return &ListUsersParams{
		Scope: &scopeDefault,

		timeout: timeout,
	}
}

// NewListUsersParamsWithContext creates a new ListUsersParams object
// with the default values initialized, and the ability to set a context for a request
func NewListUsersParamsWithContext(ctx context.Context) *ListUsersParams {
	var (
		scopeDefault = string("OWN")
	)
	return &ListUsersParams{
		Scope: &scopeDefault,

		Context: ctx,
	}
}

// NewListUsersParamsWithHTTPClient creates a new ListUsersParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListUsersParamsWithHTTPClient(client *http.Client) *ListUsersParams {
	var (
		scopeDefault = string("OWN")
	)
	return &ListUsersParams{
		Scope:      &scopeDefault,
		HTTPClient: client,
	}
}

/*ListUsersParams contains all the parameters to send to the API endpoint
for the list users operation typically these are written to a http.Request
*/
type ListUsersParams struct {

	/*Email
	  email to filter when listing

	*/
	Email *strfmt.Email
	/*Permissions
	  users permissions switch

	*/
	Permissions *bool
	/*Project
	  project uuid to filter when listing

	*/
	Project *strfmt.UUID
	/*Scope
	  organization scope switch

	*/
	Scope *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the list users params
func (o *ListUsersParams) WithTimeout(timeout time.Duration) *ListUsersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list users params
func (o *ListUsersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list users params
func (o *ListUsersParams) WithContext(ctx context.Context) *ListUsersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list users params
func (o *ListUsersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list users params
func (o *ListUsersParams) WithHTTPClient(client *http.Client) *ListUsersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list users params
func (o *ListUsersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEmail adds the email to the list users params
func (o *ListUsersParams) WithEmail(email *strfmt.Email) *ListUsersParams {
	o.SetEmail(email)
	return o
}

// SetEmail adds the email to the list users params
func (o *ListUsersParams) SetEmail(email *strfmt.Email) {
	o.Email = email
}

// WithPermissions adds the permissions to the list users params
func (o *ListUsersParams) WithPermissions(permissions *bool) *ListUsersParams {
	o.SetPermissions(permissions)
	return o
}

// SetPermissions adds the permissions to the list users params
func (o *ListUsersParams) SetPermissions(permissions *bool) {
	o.Permissions = permissions
}

// WithProject adds the project to the list users params
func (o *ListUsersParams) WithProject(project *strfmt.UUID) *ListUsersParams {
	o.SetProject(project)
	return o
}

// SetProject adds the project to the list users params
func (o *ListUsersParams) SetProject(project *strfmt.UUID) {
	o.Project = project
}

// WithScope adds the scope to the list users params
func (o *ListUsersParams) WithScope(scope *string) *ListUsersParams {
	o.SetScope(scope)
	return o
}

// SetScope adds the scope to the list users params
func (o *ListUsersParams) SetScope(scope *string) {
	o.Scope = scope
}

// WriteToRequest writes these params to a swagger request
func (o *ListUsersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Email != nil {

		// query param email
		var qrEmail strfmt.Email
		if o.Email != nil {
			qrEmail = *o.Email
		}
		qEmail := qrEmail.String()
		if qEmail != "" {
			if err := r.SetQueryParam("email", qEmail); err != nil {
				return err
			}
		}

	}

	if o.Permissions != nil {

		// query param permissions
		var qrPermissions bool
		if o.Permissions != nil {
			qrPermissions = *o.Permissions
		}
		qPermissions := swag.FormatBool(qrPermissions)
		if qPermissions != "" {
			if err := r.SetQueryParam("permissions", qPermissions); err != nil {
				return err
			}
		}

	}

	if o.Project != nil {

		// query param project
		var qrProject strfmt.UUID
		if o.Project != nil {
			qrProject = *o.Project
		}
		qProject := qrProject.String()
		if qProject != "" {
			if err := r.SetQueryParam("project", qProject); err != nil {
				return err
			}
		}

	}

	if o.Scope != nil {

		// query param scope
		var qrScope string
		if o.Scope != nil {
			qrScope = *o.Scope
		}
		qScope := qrScope
		if qScope != "" {
			if err := r.SetQueryParam("scope", qScope); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
