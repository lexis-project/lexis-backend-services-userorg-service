// Code generated by go-swagger; DO NOT EDIT.

package project_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// DeleteProjectOKCode is the HTTP code returned for type DeleteProjectOK
const DeleteProjectOKCode int = 200

/*DeleteProjectOK deleted project

swagger:response deleteProjectOK
*/
type DeleteProjectOK struct {

	/*
	  In: Body
	*/
	Payload *models.DeletedResponse `json:"body,omitempty"`
}

// NewDeleteProjectOK creates DeleteProjectOK with default headers values
func NewDeleteProjectOK() *DeleteProjectOK {

	return &DeleteProjectOK{}
}

// WithPayload adds the payload to the delete project o k response
func (o *DeleteProjectOK) WithPayload(payload *models.DeletedResponse) *DeleteProjectOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete project o k response
func (o *DeleteProjectOK) SetPayload(payload *models.DeletedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteProjectOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteProjectUnauthorizedCode is the HTTP code returned for type DeleteProjectUnauthorized
const DeleteProjectUnauthorizedCode int = 401

/*DeleteProjectUnauthorized Authorization error

swagger:response deleteProjectUnauthorized
*/
type DeleteProjectUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteProjectUnauthorized creates DeleteProjectUnauthorized with default headers values
func NewDeleteProjectUnauthorized() *DeleteProjectUnauthorized {

	return &DeleteProjectUnauthorized{}
}

// WithPayload adds the payload to the delete project unauthorized response
func (o *DeleteProjectUnauthorized) WithPayload(payload *models.ErrorResponse) *DeleteProjectUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete project unauthorized response
func (o *DeleteProjectUnauthorized) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteProjectUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteProjectForbiddenCode is the HTTP code returned for type DeleteProjectForbidden
const DeleteProjectForbiddenCode int = 403

/*DeleteProjectForbidden Authorization error

swagger:response deleteProjectForbidden
*/
type DeleteProjectForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteProjectForbidden creates DeleteProjectForbidden with default headers values
func NewDeleteProjectForbidden() *DeleteProjectForbidden {

	return &DeleteProjectForbidden{}
}

// WithPayload adds the payload to the delete project forbidden response
func (o *DeleteProjectForbidden) WithPayload(payload *models.ErrorResponse) *DeleteProjectForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete project forbidden response
func (o *DeleteProjectForbidden) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteProjectForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteProjectNotFoundCode is the HTTP code returned for type DeleteProjectNotFound
const DeleteProjectNotFoundCode int = 404

/*DeleteProjectNotFound project with not found

swagger:response deleteProjectNotFound
*/
type DeleteProjectNotFound struct {

	/*
	  In: Body
	*/
	Payload *models.MissingResponse `json:"body,omitempty"`
}

// NewDeleteProjectNotFound creates DeleteProjectNotFound with default headers values
func NewDeleteProjectNotFound() *DeleteProjectNotFound {

	return &DeleteProjectNotFound{}
}

// WithPayload adds the payload to the delete project not found response
func (o *DeleteProjectNotFound) WithPayload(payload *models.MissingResponse) *DeleteProjectNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete project not found response
func (o *DeleteProjectNotFound) SetPayload(payload *models.MissingResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteProjectNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteProjectInternalServerErrorCode is the HTTP code returned for type DeleteProjectInternalServerError
const DeleteProjectInternalServerErrorCode int = 500

/*DeleteProjectInternalServerError unexpected error

swagger:response deleteProjectInternalServerError
*/
type DeleteProjectInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteProjectInternalServerError creates DeleteProjectInternalServerError with default headers values
func NewDeleteProjectInternalServerError() *DeleteProjectInternalServerError {

	return &DeleteProjectInternalServerError{}
}

// WithPayload adds the payload to the delete project internal server error response
func (o *DeleteProjectInternalServerError) WithPayload(payload *models.ErrorResponse) *DeleteProjectInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete project internal server error response
func (o *DeleteProjectInternalServerError) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteProjectInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
