// Code generated by go-swagger; DO NOT EDIT.

package hpc_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// DeleteHPCResourceReader is a Reader for the DeleteHPCResource structure.
type DeleteHPCResourceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteHPCResourceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteHPCResourceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteHPCResourceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteHPCResourceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteHPCResourceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteHPCResourceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteHPCResourceOK creates a DeleteHPCResourceOK with default headers values
func NewDeleteHPCResourceOK() *DeleteHPCResourceOK {
	return &DeleteHPCResourceOK{}
}

/*DeleteHPCResourceOK handles this case with default header values.

deleted HPCResource
*/
type DeleteHPCResourceOK struct {
	Payload *models.DeletedResponse
}

func (o *DeleteHPCResourceOK) Error() string {
	return fmt.Sprintf("[DELETE /hpc/resource/{id}][%d] deleteHPCResourceOK  %+v", 200, o.Payload)
}

func (o *DeleteHPCResourceOK) GetPayload() *models.DeletedResponse {
	return o.Payload
}

func (o *DeleteHPCResourceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DeletedResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteHPCResourceUnauthorized creates a DeleteHPCResourceUnauthorized with default headers values
func NewDeleteHPCResourceUnauthorized() *DeleteHPCResourceUnauthorized {
	return &DeleteHPCResourceUnauthorized{}
}

/*DeleteHPCResourceUnauthorized handles this case with default header values.

Authorization error
*/
type DeleteHPCResourceUnauthorized struct {
	Payload *models.ErrorResponse
}

func (o *DeleteHPCResourceUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /hpc/resource/{id}][%d] deleteHPCResourceUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteHPCResourceUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *DeleteHPCResourceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteHPCResourceForbidden creates a DeleteHPCResourceForbidden with default headers values
func NewDeleteHPCResourceForbidden() *DeleteHPCResourceForbidden {
	return &DeleteHPCResourceForbidden{}
}

/*DeleteHPCResourceForbidden handles this case with default header values.

Authorization error
*/
type DeleteHPCResourceForbidden struct {
	Payload *models.ErrorResponse
}

func (o *DeleteHPCResourceForbidden) Error() string {
	return fmt.Sprintf("[DELETE /hpc/resource/{id}][%d] deleteHPCResourceForbidden  %+v", 403, o.Payload)
}

func (o *DeleteHPCResourceForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *DeleteHPCResourceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteHPCResourceNotFound creates a DeleteHPCResourceNotFound with default headers values
func NewDeleteHPCResourceNotFound() *DeleteHPCResourceNotFound {
	return &DeleteHPCResourceNotFound{}
}

/*DeleteHPCResourceNotFound handles this case with default header values.

HPCResource with not found
*/
type DeleteHPCResourceNotFound struct {
	Payload *models.MissingResponse
}

func (o *DeleteHPCResourceNotFound) Error() string {
	return fmt.Sprintf("[DELETE /hpc/resource/{id}][%d] deleteHPCResourceNotFound  %+v", 404, o.Payload)
}

func (o *DeleteHPCResourceNotFound) GetPayload() *models.MissingResponse {
	return o.Payload
}

func (o *DeleteHPCResourceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MissingResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteHPCResourceInternalServerError creates a DeleteHPCResourceInternalServerError with default headers values
func NewDeleteHPCResourceInternalServerError() *DeleteHPCResourceInternalServerError {
	return &DeleteHPCResourceInternalServerError{}
}

/*DeleteHPCResourceInternalServerError handles this case with default header values.

unexpected error
*/
type DeleteHPCResourceInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *DeleteHPCResourceInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /hpc/resource/{id}][%d] deleteHPCResourceInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteHPCResourceInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *DeleteHPCResourceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
