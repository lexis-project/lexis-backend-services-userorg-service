// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ConflictResponse conflict response
//
// swagger:model ConflictResponse
type ConflictResponse struct {

	// ID
	ID string `json:"ID,omitempty"`

	// message
	Message string `json:"Message,omitempty"`
}

// Validate validates this conflict response
func (m *ConflictResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ConflictResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConflictResponse) UnmarshalBinary(b []byte) error {
	var res ConflictResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
