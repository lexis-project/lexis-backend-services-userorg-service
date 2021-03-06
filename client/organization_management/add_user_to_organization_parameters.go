// Code generated by go-swagger; DO NOT EDIT.

package organization_management

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
)

// NewAddUserToOrganizationParams creates a new AddUserToOrganizationParams object
// with the default values initialized.
func NewAddUserToOrganizationParams() *AddUserToOrganizationParams {
	var ()
	return &AddUserToOrganizationParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAddUserToOrganizationParamsWithTimeout creates a new AddUserToOrganizationParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAddUserToOrganizationParamsWithTimeout(timeout time.Duration) *AddUserToOrganizationParams {
	var ()
	return &AddUserToOrganizationParams{

		timeout: timeout,
	}
}

// NewAddUserToOrganizationParamsWithContext creates a new AddUserToOrganizationParams object
// with the default values initialized, and the ability to set a context for a request
func NewAddUserToOrganizationParamsWithContext(ctx context.Context) *AddUserToOrganizationParams {
	var ()
	return &AddUserToOrganizationParams{

		Context: ctx,
	}
}

// NewAddUserToOrganizationParamsWithHTTPClient creates a new AddUserToOrganizationParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAddUserToOrganizationParamsWithHTTPClient(client *http.Client) *AddUserToOrganizationParams {
	var ()
	return &AddUserToOrganizationParams{
		HTTPClient: client,
	}
}

/*AddUserToOrganizationParams contains all the parameters to send to the API endpoint
for the add user to organization operation typically these are written to a http.Request
*/
type AddUserToOrganizationParams struct {

	/*ID
	  Id of organization to be obtained

	*/
	ID strfmt.UUID
	/*UserID
	  Id of user to be added

	*/
	UserID strfmt.UUID

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the add user to organization params
func (o *AddUserToOrganizationParams) WithTimeout(timeout time.Duration) *AddUserToOrganizationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the add user to organization params
func (o *AddUserToOrganizationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the add user to organization params
func (o *AddUserToOrganizationParams) WithContext(ctx context.Context) *AddUserToOrganizationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the add user to organization params
func (o *AddUserToOrganizationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the add user to organization params
func (o *AddUserToOrganizationParams) WithHTTPClient(client *http.Client) *AddUserToOrganizationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the add user to organization params
func (o *AddUserToOrganizationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the add user to organization params
func (o *AddUserToOrganizationParams) WithID(id strfmt.UUID) *AddUserToOrganizationParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the add user to organization params
func (o *AddUserToOrganizationParams) SetID(id strfmt.UUID) {
	o.ID = id
}

// WithUserID adds the userID to the add user to organization params
func (o *AddUserToOrganizationParams) WithUserID(userID strfmt.UUID) *AddUserToOrganizationParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the add user to organization params
func (o *AddUserToOrganizationParams) SetUserID(userID strfmt.UUID) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *AddUserToOrganizationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID.String()); err != nil {
		return err
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID.String()); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
