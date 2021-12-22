// Code generated by go-swagger; DO NOT EDIT.

package hpc_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// CreateHPCResourceCreatedCode is the HTTP code returned for type CreateHPCResourceCreated
const CreateHPCResourceCreatedCode int = 201

/*CreateHPCResourceCreated HPCResource created

swagger:response createHPCResourceCreated
*/
type CreateHPCResourceCreated struct {

	/*
	  In: Body
	*/
	Payload *models.CreatedResponse `json:"body,omitempty"`
}

// NewCreateHPCResourceCreated creates CreateHPCResourceCreated with default headers values
func NewCreateHPCResourceCreated() *CreateHPCResourceCreated {

	return &CreateHPCResourceCreated{}
}

// WithPayload adds the payload to the create h p c resource created response
func (o *CreateHPCResourceCreated) WithPayload(payload *models.CreatedResponse) *CreateHPCResourceCreated {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create h p c resource created response
func (o *CreateHPCResourceCreated) SetPayload(payload *models.CreatedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateHPCResourceCreated) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(201)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateHPCResourceUnauthorizedCode is the HTTP code returned for type CreateHPCResourceUnauthorized
const CreateHPCResourceUnauthorizedCode int = 401

/*CreateHPCResourceUnauthorized Authorization error

swagger:response createHPCResourceUnauthorized
*/
type CreateHPCResourceUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewCreateHPCResourceUnauthorized creates CreateHPCResourceUnauthorized with default headers values
func NewCreateHPCResourceUnauthorized() *CreateHPCResourceUnauthorized {

	return &CreateHPCResourceUnauthorized{}
}

// WithPayload adds the payload to the create h p c resource unauthorized response
func (o *CreateHPCResourceUnauthorized) WithPayload(payload *models.ErrorResponse) *CreateHPCResourceUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create h p c resource unauthorized response
func (o *CreateHPCResourceUnauthorized) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateHPCResourceUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateHPCResourceForbiddenCode is the HTTP code returned for type CreateHPCResourceForbidden
const CreateHPCResourceForbiddenCode int = 403

/*CreateHPCResourceForbidden Authorization error

swagger:response createHPCResourceForbidden
*/
type CreateHPCResourceForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewCreateHPCResourceForbidden creates CreateHPCResourceForbidden with default headers values
func NewCreateHPCResourceForbidden() *CreateHPCResourceForbidden {

	return &CreateHPCResourceForbidden{}
}

// WithPayload adds the payload to the create h p c resource forbidden response
func (o *CreateHPCResourceForbidden) WithPayload(payload *models.ErrorResponse) *CreateHPCResourceForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create h p c resource forbidden response
func (o *CreateHPCResourceForbidden) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateHPCResourceForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateHPCResourceConflictCode is the HTTP code returned for type CreateHPCResourceConflict
const CreateHPCResourceConflictCode int = 409

/*CreateHPCResourceConflict an existing item already exists

swagger:response createHPCResourceConflict
*/
type CreateHPCResourceConflict struct {

	/*
	  In: Body
	*/
	Payload *models.ConflictResponse `json:"body,omitempty"`
}

// NewCreateHPCResourceConflict creates CreateHPCResourceConflict with default headers values
func NewCreateHPCResourceConflict() *CreateHPCResourceConflict {

	return &CreateHPCResourceConflict{}
}

// WithPayload adds the payload to the create h p c resource conflict response
func (o *CreateHPCResourceConflict) WithPayload(payload *models.ConflictResponse) *CreateHPCResourceConflict {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create h p c resource conflict response
func (o *CreateHPCResourceConflict) SetPayload(payload *models.ConflictResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateHPCResourceConflict) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(409)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateHPCResourceInternalServerErrorCode is the HTTP code returned for type CreateHPCResourceInternalServerError
const CreateHPCResourceInternalServerErrorCode int = 500

/*CreateHPCResourceInternalServerError unexpected error

swagger:response createHPCResourceInternalServerError
*/
type CreateHPCResourceInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewCreateHPCResourceInternalServerError creates CreateHPCResourceInternalServerError with default headers values
func NewCreateHPCResourceInternalServerError() *CreateHPCResourceInternalServerError {

	return &CreateHPCResourceInternalServerError{}
}

// WithPayload adds the payload to the create h p c resource internal server error response
func (o *CreateHPCResourceInternalServerError) WithPayload(payload *models.ErrorResponse) *CreateHPCResourceInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create h p c resource internal server error response
func (o *CreateHPCResourceInternalServerError) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateHPCResourceInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
