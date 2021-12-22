// Code generated by go-swagger; DO NOT EDIT.

package organization_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// DeleteUserFromOrganizationOKCode is the HTTP code returned for type DeleteUserFromOrganizationOK
const DeleteUserFromOrganizationOKCode int = 200

/*DeleteUserFromOrganizationOK deleted user from organization

swagger:response deleteUserFromOrganizationOK
*/
type DeleteUserFromOrganizationOK struct {

	/*
	  In: Body
	*/
	Payload *models.DeletedResponse `json:"body,omitempty"`
}

// NewDeleteUserFromOrganizationOK creates DeleteUserFromOrganizationOK with default headers values
func NewDeleteUserFromOrganizationOK() *DeleteUserFromOrganizationOK {

	return &DeleteUserFromOrganizationOK{}
}

// WithPayload adds the payload to the delete user from organization o k response
func (o *DeleteUserFromOrganizationOK) WithPayload(payload *models.DeletedResponse) *DeleteUserFromOrganizationOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete user from organization o k response
func (o *DeleteUserFromOrganizationOK) SetPayload(payload *models.DeletedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteUserFromOrganizationOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteUserFromOrganizationUnauthorizedCode is the HTTP code returned for type DeleteUserFromOrganizationUnauthorized
const DeleteUserFromOrganizationUnauthorizedCode int = 401

/*DeleteUserFromOrganizationUnauthorized Authorization error

swagger:response deleteUserFromOrganizationUnauthorized
*/
type DeleteUserFromOrganizationUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteUserFromOrganizationUnauthorized creates DeleteUserFromOrganizationUnauthorized with default headers values
func NewDeleteUserFromOrganizationUnauthorized() *DeleteUserFromOrganizationUnauthorized {

	return &DeleteUserFromOrganizationUnauthorized{}
}

// WithPayload adds the payload to the delete user from organization unauthorized response
func (o *DeleteUserFromOrganizationUnauthorized) WithPayload(payload *models.ErrorResponse) *DeleteUserFromOrganizationUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete user from organization unauthorized response
func (o *DeleteUserFromOrganizationUnauthorized) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteUserFromOrganizationUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteUserFromOrganizationForbiddenCode is the HTTP code returned for type DeleteUserFromOrganizationForbidden
const DeleteUserFromOrganizationForbiddenCode int = 403

/*DeleteUserFromOrganizationForbidden Authorization error

swagger:response deleteUserFromOrganizationForbidden
*/
type DeleteUserFromOrganizationForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteUserFromOrganizationForbidden creates DeleteUserFromOrganizationForbidden with default headers values
func NewDeleteUserFromOrganizationForbidden() *DeleteUserFromOrganizationForbidden {

	return &DeleteUserFromOrganizationForbidden{}
}

// WithPayload adds the payload to the delete user from organization forbidden response
func (o *DeleteUserFromOrganizationForbidden) WithPayload(payload *models.ErrorResponse) *DeleteUserFromOrganizationForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete user from organization forbidden response
func (o *DeleteUserFromOrganizationForbidden) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteUserFromOrganizationForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteUserFromOrganizationNotFoundCode is the HTTP code returned for type DeleteUserFromOrganizationNotFound
const DeleteUserFromOrganizationNotFoundCode int = 404

/*DeleteUserFromOrganizationNotFound organization or user not found

swagger:response deleteUserFromOrganizationNotFound
*/
type DeleteUserFromOrganizationNotFound struct {

	/*
	  In: Body
	*/
	Payload *models.MissingResponse `json:"body,omitempty"`
}

// NewDeleteUserFromOrganizationNotFound creates DeleteUserFromOrganizationNotFound with default headers values
func NewDeleteUserFromOrganizationNotFound() *DeleteUserFromOrganizationNotFound {

	return &DeleteUserFromOrganizationNotFound{}
}

// WithPayload adds the payload to the delete user from organization not found response
func (o *DeleteUserFromOrganizationNotFound) WithPayload(payload *models.MissingResponse) *DeleteUserFromOrganizationNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete user from organization not found response
func (o *DeleteUserFromOrganizationNotFound) SetPayload(payload *models.MissingResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteUserFromOrganizationNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteUserFromOrganizationInternalServerErrorCode is the HTTP code returned for type DeleteUserFromOrganizationInternalServerError
const DeleteUserFromOrganizationInternalServerErrorCode int = 500

/*DeleteUserFromOrganizationInternalServerError unexpected error

swagger:response deleteUserFromOrganizationInternalServerError
*/
type DeleteUserFromOrganizationInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteUserFromOrganizationInternalServerError creates DeleteUserFromOrganizationInternalServerError with default headers values
func NewDeleteUserFromOrganizationInternalServerError() *DeleteUserFromOrganizationInternalServerError {

	return &DeleteUserFromOrganizationInternalServerError{}
}

// WithPayload adds the payload to the delete user from organization internal server error response
func (o *DeleteUserFromOrganizationInternalServerError) WithPayload(payload *models.ErrorResponse) *DeleteUserFromOrganizationInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete user from organization internal server error response
func (o *DeleteUserFromOrganizationInternalServerError) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteUserFromOrganizationInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}