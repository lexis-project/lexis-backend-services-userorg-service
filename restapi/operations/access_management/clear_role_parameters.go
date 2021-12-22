// Code generated by go-swagger; DO NOT EDIT.

package access_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// NewClearRoleParams creates a new ClearRoleParams object
// no default values defined in spec.
func NewClearRoleParams() ClearRoleParams {

	return ClearRoleParams{}
}

// ClearRoleParams contains all the bound params for the clear role operation
// typically these are obtained from a http.Request
//
// swagger:parameters clearRole
type ClearRoleParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Id of the organization linked
	  Required: true
	  In: query
	*/
	OrganizationID strfmt.UUID
	/*Id of the project linked
	  In: query
	*/
	ProjectID *strfmt.UUID
	/*Short name of the project linked
	  In: query
	*/
	ProjectShortName *string
	/*Id of the user to be modified
	  Required: true
	  In: path
	*/
	UserID strfmt.UUID
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewClearRoleParams() beforehand.
func (o *ClearRoleParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qOrganizationID, qhkOrganizationID, _ := qs.GetOK("organizationID")
	if err := o.bindOrganizationID(qOrganizationID, qhkOrganizationID, route.Formats); err != nil {
		res = append(res, err)
	}

	qProjectID, qhkProjectID, _ := qs.GetOK("projectID")
	if err := o.bindProjectID(qProjectID, qhkProjectID, route.Formats); err != nil {
		res = append(res, err)
	}

	qProjectShortName, qhkProjectShortName, _ := qs.GetOK("projectShortName")
	if err := o.bindProjectShortName(qProjectShortName, qhkProjectShortName, route.Formats); err != nil {
		res = append(res, err)
	}

	rUserID, rhkUserID, _ := route.Params.GetOK("userID")
	if err := o.bindUserID(rUserID, rhkUserID, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindOrganizationID binds and validates parameter OrganizationID from query.
func (o *ClearRoleParams) bindOrganizationID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("organizationID", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false
	if err := validate.RequiredString("organizationID", "query", raw); err != nil {
		return err
	}

	// Format: uuid
	value, err := formats.Parse("uuid", raw)
	if err != nil {
		return errors.InvalidType("organizationID", "query", "strfmt.UUID", raw)
	}
	o.OrganizationID = *(value.(*strfmt.UUID))

	if err := o.validateOrganizationID(formats); err != nil {
		return err
	}

	return nil
}

// validateOrganizationID carries on validations for parameter OrganizationID
func (o *ClearRoleParams) validateOrganizationID(formats strfmt.Registry) error {

	if err := validate.FormatOf("organizationID", "query", "uuid", o.OrganizationID.String(), formats); err != nil {
		return err
	}
	return nil
}

// bindProjectID binds and validates parameter ProjectID from query.
func (o *ClearRoleParams) bindProjectID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	// Format: uuid
	value, err := formats.Parse("uuid", raw)
	if err != nil {
		return errors.InvalidType("projectID", "query", "strfmt.UUID", raw)
	}
	o.ProjectID = (value.(*strfmt.UUID))

	if err := o.validateProjectID(formats); err != nil {
		return err
	}

	return nil
}

// validateProjectID carries on validations for parameter ProjectID
func (o *ClearRoleParams) validateProjectID(formats strfmt.Registry) error {

	if err := validate.FormatOf("projectID", "query", "uuid", o.ProjectID.String(), formats); err != nil {
		return err
	}
	return nil
}

// bindProjectShortName binds and validates parameter ProjectShortName from query.
func (o *ClearRoleParams) bindProjectShortName(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.ProjectShortName = &raw

	return nil
}

// bindUserID binds and validates parameter UserID from path.
func (o *ClearRoleParams) bindUserID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route

	// Format: uuid
	value, err := formats.Parse("uuid", raw)
	if err != nil {
		return errors.InvalidType("userID", "path", "strfmt.UUID", raw)
	}
	o.UserID = *(value.(*strfmt.UUID))

	if err := o.validateUserID(formats); err != nil {
		return err
	}

	return nil
}

// validateUserID carries on validations for parameter UserID
func (o *ClearRoleParams) validateUserID(formats strfmt.Registry) error {

	if err := validate.FormatOf("userID", "path", "uuid", o.UserID.String(), formats); err != nil {
		return err
	}
	return nil
}
