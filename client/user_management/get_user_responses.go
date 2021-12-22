// Code generated by go-swagger; DO NOT EDIT.

package user_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
)

// GetUserReader is a Reader for the GetUser structure.
type GetUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetUserInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetUserOK creates a GetUserOK with default headers values
func NewGetUserOK() *GetUserOK {
	return &GetUserOK{}
}

/*GetUserOK handles this case with default header values.

user returned
*/
type GetUserOK struct {
	Payload *models.User
}

func (o *GetUserOK) Error() string {
	return fmt.Sprintf("[GET /user/{id}][%d] getUserOK  %+v", 200, o.Payload)
}

func (o *GetUserOK) GetPayload() *models.User {
	return o.Payload
}

func (o *GetUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.User)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserUnauthorized creates a GetUserUnauthorized with default headers values
func NewGetUserUnauthorized() *GetUserUnauthorized {
	return &GetUserUnauthorized{}
}

/*GetUserUnauthorized handles this case with default header values.

Authorization error
*/
type GetUserUnauthorized struct {
	Payload *models.ErrorResponse
}

func (o *GetUserUnauthorized) Error() string {
	return fmt.Sprintf("[GET /user/{id}][%d] getUserUnauthorized  %+v", 401, o.Payload)
}

func (o *GetUserUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserForbidden creates a GetUserForbidden with default headers values
func NewGetUserForbidden() *GetUserForbidden {
	return &GetUserForbidden{}
}

/*GetUserForbidden handles this case with default header values.

Authorization error
*/
type GetUserForbidden struct {
	Payload *models.ErrorResponse
}

func (o *GetUserForbidden) Error() string {
	return fmt.Sprintf("[GET /user/{id}][%d] getUserForbidden  %+v", 403, o.Payload)
}

func (o *GetUserForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserNotFound creates a GetUserNotFound with default headers values
func NewGetUserNotFound() *GetUserNotFound {
	return &GetUserNotFound{}
}

/*GetUserNotFound handles this case with default header values.

user with userId not found
*/
type GetUserNotFound struct {
	Payload *models.MissingResponse
}

func (o *GetUserNotFound) Error() string {
	return fmt.Sprintf("[GET /user/{id}][%d] getUserNotFound  %+v", 404, o.Payload)
}

func (o *GetUserNotFound) GetPayload() *models.MissingResponse {
	return o.Payload
}

func (o *GetUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MissingResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserInternalServerError creates a GetUserInternalServerError with default headers values
func NewGetUserInternalServerError() *GetUserInternalServerError {
	return &GetUserInternalServerError{}
}

/*GetUserInternalServerError handles this case with default header values.

unexpected error
*/
type GetUserInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *GetUserInternalServerError) Error() string {
	return fmt.Sprintf("[GET /user/{id}][%d] getUserInternalServerError  %+v", 500, o.Payload)
}

func (o *GetUserInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetUserInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
