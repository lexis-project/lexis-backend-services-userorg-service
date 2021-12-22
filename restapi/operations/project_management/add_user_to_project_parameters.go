// Code generated by go-swagger; DO NOT EDIT.

package project_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// NewAddUserToProjectParams creates a new AddUserToProjectParams object
// no default values defined in spec.
func NewAddUserToProjectParams() AddUserToProjectParams {

	return AddUserToProjectParams{}
}

// AddUserToProjectParams contains all the bound params for the add user to project operation
// typically these are obtained from a http.Request
//
// swagger:parameters addUserToProject
type AddUserToProjectParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Id of project to be obtained
	  Required: true
	  In: path
	*/
	ID strfmt.UUID
	/*Id of user to be added
	  Required: true
	  In: path
	*/
	UserID strfmt.UUID
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewAddUserToProjectParams() beforehand.
func (o *AddUserToProjectParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	rID, rhkID, _ := route.Params.GetOK("id")
	if err := o.bindID(rID, rhkID, route.Formats); err != nil {
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

// bindID binds and validates parameter ID from path.
func (o *AddUserToProjectParams) bindID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route

	// Format: uuid
	value, err := formats.Parse("uuid", raw)
	if err != nil {
		return errors.InvalidType("id", "path", "strfmt.UUID", raw)
	}
	o.ID = *(value.(*strfmt.UUID))

	if err := o.validateID(formats); err != nil {
		return err
	}

	return nil
}

// validateID carries on validations for parameter ID
func (o *AddUserToProjectParams) validateID(formats strfmt.Registry) error {

	if err := validate.FormatOf("id", "path", "uuid", o.ID.String(), formats); err != nil {
		return err
	}
	return nil
}

// bindUserID binds and validates parameter UserID from path.
func (o *AddUserToProjectParams) bindUserID(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *AddUserToProjectParams) validateUserID(formats strfmt.Registry) error {

	if err := validate.FormatOf("userID", "path", "uuid", o.UserID.String(), formats); err != nil {
		return err
	}
	return nil
}
