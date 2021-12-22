// Code generated by go-swagger; DO NOT EDIT.

package organization_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// NewUpdateOrganizationParams creates a new UpdateOrganizationParams object
// no default values defined in spec.
func NewUpdateOrganizationParams() UpdateOrganizationParams {

	return UpdateOrganizationParams{}
}

// UpdateOrganizationParams contains all the bound params for the update organization operation
// typically these are obtained from a http.Request
//
// swagger:parameters updateOrganization
type UpdateOrganizationParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Id of organization to be obtained
	  Required: true
	  In: path
	*/
	ID strfmt.UUID
	/*updated organization data to be added
	  Required: true
	  In: body
	*/
	Organization *models.Organization
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewUpdateOrganizationParams() beforehand.
func (o *UpdateOrganizationParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	rID, rhkID, _ := route.Params.GetOK("id")
	if err := o.bindID(rID, rhkID, route.Formats); err != nil {
		res = append(res, err)
	}

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.Organization
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("organization", "body", ""))
			} else {
				res = append(res, errors.NewParseError("organization", "body", "", err))
			}
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.Organization = &body
			}
		}
	} else {
		res = append(res, errors.Required("organization", "body", ""))
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindID binds and validates parameter ID from path.
func (o *UpdateOrganizationParams) bindID(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *UpdateOrganizationParams) validateID(formats strfmt.Registry) error {

	if err := validate.FormatOf("id", "path", "uuid", o.ID.String(), formats); err != nil {
		return err
	}
	return nil
}
