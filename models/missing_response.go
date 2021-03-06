// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MissingResponse missing response
//
// swagger:model MissingResponse
type MissingResponse struct {

	// ID
	ID string `json:"ID,omitempty"`

	// message
	Message string `json:"Message,omitempty"`
}

// Validate validates this missing response
func (m *MissingResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MissingResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MissingResponse) UnmarshalBinary(b []byte) error {
	var res MissingResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
