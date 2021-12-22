// Code generated by go-swagger; DO NOT EDIT.

package access_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// ClearRoleReader is a Reader for the ClearRole structure.
type ClearRoleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ClearRoleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewClearRoleOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewClearRoleUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewClearRoleForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewClearRoleNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewClearRoleInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewClearRoleOK creates a ClearRoleOK with default headers values
func NewClearRoleOK() *ClearRoleOK {
	return &ClearRoleOK{}
}

/*ClearRoleOK handles this case with default header values.

Role added successfully
*/
type ClearRoleOK struct {
	Payload *models.RoleAdded
}

func (o *ClearRoleOK) Error() string {
	return fmt.Sprintf("[POST /authz/{userID}/clear][%d] clearRoleOK  %+v", 200, o.Payload)
}

func (o *ClearRoleOK) GetPayload() *models.RoleAdded {
	return o.Payload
}

func (o *ClearRoleOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RoleAdded)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewClearRoleUnauthorized creates a ClearRoleUnauthorized with default headers values
func NewClearRoleUnauthorized() *ClearRoleUnauthorized {
	return &ClearRoleUnauthorized{}
}

/*ClearRoleUnauthorized handles this case with default header values.

Authorization error
*/
type ClearRoleUnauthorized struct {
	Payload *models.ErrorResponse
}

func (o *ClearRoleUnauthorized) Error() string {
	return fmt.Sprintf("[POST /authz/{userID}/clear][%d] clearRoleUnauthorized  %+v", 401, o.Payload)
}

func (o *ClearRoleUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ClearRoleUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewClearRoleForbidden creates a ClearRoleForbidden with default headers values
func NewClearRoleForbidden() *ClearRoleForbidden {
	return &ClearRoleForbidden{}
}

/*ClearRoleForbidden handles this case with default header values.

Authorization error
*/
type ClearRoleForbidden struct {
	Payload *models.ErrorResponse
}

func (o *ClearRoleForbidden) Error() string {
	return fmt.Sprintf("[POST /authz/{userID}/clear][%d] clearRoleForbidden  %+v", 403, o.Payload)
}

func (o *ClearRoleForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ClearRoleForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewClearRoleNotFound creates a ClearRoleNotFound with default headers values
func NewClearRoleNotFound() *ClearRoleNotFound {
	return &ClearRoleNotFound{}
}

/*ClearRoleNotFound handles this case with default header values.

user/org/prj not found
*/
type ClearRoleNotFound struct {
	Payload *models.MissingResponse
}

func (o *ClearRoleNotFound) Error() string {
	return fmt.Sprintf("[POST /authz/{userID}/clear][%d] clearRoleNotFound  %+v", 404, o.Payload)
}

func (o *ClearRoleNotFound) GetPayload() *models.MissingResponse {
	return o.Payload
}

func (o *ClearRoleNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MissingResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewClearRoleInternalServerError creates a ClearRoleInternalServerError with default headers values
func NewClearRoleInternalServerError() *ClearRoleInternalServerError {
	return &ClearRoleInternalServerError{}
}

/*ClearRoleInternalServerError handles this case with default header values.

unexpected error
*/
type ClearRoleInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *ClearRoleInternalServerError) Error() string {
	return fmt.Sprintf("[POST /authz/{userID}/clear][%d] clearRoleInternalServerError  %+v", 500, o.Payload)
}

func (o *ClearRoleInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ClearRoleInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
