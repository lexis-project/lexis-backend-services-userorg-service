// Code generated by go-swagger; DO NOT EDIT.

package access_management

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

// NewAddRoleParams creates a new AddRoleParams object
// with the default values initialized.
func NewAddRoleParams() *AddRoleParams {
	var ()
	return &AddRoleParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAddRoleParamsWithTimeout creates a new AddRoleParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAddRoleParamsWithTimeout(timeout time.Duration) *AddRoleParams {
	var ()
	return &AddRoleParams{

		timeout: timeout,
	}
}

// NewAddRoleParamsWithContext creates a new AddRoleParams object
// with the default values initialized, and the ability to set a context for a request
func NewAddRoleParamsWithContext(ctx context.Context) *AddRoleParams {
	var ()
	return &AddRoleParams{

		Context: ctx,
	}
}

// NewAddRoleParamsWithHTTPClient creates a new AddRoleParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAddRoleParamsWithHTTPClient(client *http.Client) *AddRoleParams {
	var ()
	return &AddRoleParams{
		HTTPClient: client,
	}
}

/*AddRoleParams contains all the parameters to send to the API endpoint
for the add role operation typically these are written to a http.Request
*/
type AddRoleParams struct {

	/*OrganizationID
	  Id of the organization linked

	*/
	OrganizationID strfmt.UUID
	/*ProjectID
	  Id of the project linked

	*/
	ProjectID *strfmt.UUID
	/*ProjectShortName
	  Short name of the project linked

	*/
	ProjectShortName *string
	/*Role
	  role to be added

	*/
	Role string
	/*UserID
	  Id of the user to be modified

	*/
	UserID strfmt.UUID

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the add role params
func (o *AddRoleParams) WithTimeout(timeout time.Duration) *AddRoleParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the add role params
func (o *AddRoleParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the add role params
func (o *AddRoleParams) WithContext(ctx context.Context) *AddRoleParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the add role params
func (o *AddRoleParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the add role params
func (o *AddRoleParams) WithHTTPClient(client *http.Client) *AddRoleParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the add role params
func (o *AddRoleParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOrganizationID adds the organizationID to the add role params
func (o *AddRoleParams) WithOrganizationID(organizationID strfmt.UUID) *AddRoleParams {
	o.SetOrganizationID(organizationID)
	return o
}

// SetOrganizationID adds the organizationId to the add role params
func (o *AddRoleParams) SetOrganizationID(organizationID strfmt.UUID) {
	o.OrganizationID = organizationID
}

// WithProjectID adds the projectID to the add role params
func (o *AddRoleParams) WithProjectID(projectID *strfmt.UUID) *AddRoleParams {
	o.SetProjectID(projectID)
	return o
}

// SetProjectID adds the projectId to the add role params
func (o *AddRoleParams) SetProjectID(projectID *strfmt.UUID) {
	o.ProjectID = projectID
}

// WithProjectShortName adds the projectShortName to the add role params
func (o *AddRoleParams) WithProjectShortName(projectShortName *string) *AddRoleParams {
	o.SetProjectShortName(projectShortName)
	return o
}

// SetProjectShortName adds the projectShortName to the add role params
func (o *AddRoleParams) SetProjectShortName(projectShortName *string) {
	o.ProjectShortName = projectShortName
}

// WithRole adds the role to the add role params
func (o *AddRoleParams) WithRole(role string) *AddRoleParams {
	o.SetRole(role)
	return o
}

// SetRole adds the role to the add role params
func (o *AddRoleParams) SetRole(role string) {
	o.Role = role
}

// WithUserID adds the userID to the add role params
func (o *AddRoleParams) WithUserID(userID strfmt.UUID) *AddRoleParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the add role params
func (o *AddRoleParams) SetUserID(userID strfmt.UUID) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *AddRoleParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param organizationID
	qrOrganizationID := o.OrganizationID
	qOrganizationID := qrOrganizationID.String()
	if qOrganizationID != "" {
		if err := r.SetQueryParam("organizationID", qOrganizationID); err != nil {
			return err
		}
	}

	if o.ProjectID != nil {

		// query param projectID
		var qrProjectID strfmt.UUID
		if o.ProjectID != nil {
			qrProjectID = *o.ProjectID
		}
		qProjectID := qrProjectID.String()
		if qProjectID != "" {
			if err := r.SetQueryParam("projectID", qProjectID); err != nil {
				return err
			}
		}

	}

	if o.ProjectShortName != nil {

		// query param projectShortName
		var qrProjectShortName string
		if o.ProjectShortName != nil {
			qrProjectShortName = *o.ProjectShortName
		}
		qProjectShortName := qrProjectShortName
		if qProjectShortName != "" {
			if err := r.SetQueryParam("projectShortName", qProjectShortName); err != nil {
				return err
			}
		}

	}

	// path param role
	if err := r.SetPathParam("role", o.Role); err != nil {
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
