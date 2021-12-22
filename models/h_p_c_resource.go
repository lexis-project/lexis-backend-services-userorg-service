// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// HPCResource h p c resource
//
// swagger:model HPCResource
type HPCResource struct {

	// approval status
	// Enum: [ACCEPTED REJECTED PENDING]
	ApprovalStatus string `json:"ApprovalStatus,omitempty" gorm:"column:approvalstatus"`

	// associated h p c project
	AssociatedHPCProject string `json:"AssociatedHPCProject,omitempty" gorm:"column:associatedhpcproject"`

	// associated l e x i s project
	// Format: uuid
	AssociatedLEXISProject strfmt.UUID `json:"AssociatedLEXISProject,omitempty" gorm:"column:associatedlexisproject;type:uuid"`

	// cloud network name
	CloudNetworkName string `json:"CloudNetworkName,omitempty" gorm:"column:cloudnetworkname"`

	// h e app e endpoint
	HEAppEEndpoint string `json:"HEAppEEndpoint,omitempty" gorm:"column:heappeendpoint"`

	// h p c provider
	// Enum: [IT4I LRZ ICHEC]
	HPCProvider string `json:"HPCProvider,omitempty" gorm:"column:hpcprovider"`

	// h p c resource ID
	HPCResourceID string `json:"HPCResourceID,omitempty" gorm:"column:hpcresourceid;primary_key;unique;default:md5(random()::text || clock_timestamp()::text)::uuid"`

	// open stack endpoint
	OpenStackEndpoint string `json:"OpenStackEndpoint,omitempty" gorm:"column:openstackendpoint"`

	// open stack project ID
	OpenStackProjectID string `json:"OpenStackProjectID,omitempty" gorm:"column:openstackprojectid"`

	// project network name
	ProjectNetworkName string `json:"ProjectNetworkName,omitempty" gorm:"column:projectnetworkname"`

	// resource type
	// Enum: [CLOUD HPC SMARTGW]
	ResourceType string `json:"ResourceType,omitempty" gorm:"column:resourcetype"`

	// terms consent
	TermsConsent bool `json:"TermsConsent,omitempty" gorm:"column:termsconsent;type:bool"`
}

// Validate validates this h p c resource
func (m *HPCResource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApprovalStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssociatedLEXISProject(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHPCProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var hPCResourceTypeApprovalStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ACCEPTED","REJECTED","PENDING"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		hPCResourceTypeApprovalStatusPropEnum = append(hPCResourceTypeApprovalStatusPropEnum, v)
	}
}

const (

	// HPCResourceApprovalStatusACCEPTED captures enum value "ACCEPTED"
	HPCResourceApprovalStatusACCEPTED string = "ACCEPTED"

	// HPCResourceApprovalStatusREJECTED captures enum value "REJECTED"
	HPCResourceApprovalStatusREJECTED string = "REJECTED"

	// HPCResourceApprovalStatusPENDING captures enum value "PENDING"
	HPCResourceApprovalStatusPENDING string = "PENDING"
)

// prop value enum
func (m *HPCResource) validateApprovalStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, hPCResourceTypeApprovalStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *HPCResource) validateApprovalStatus(formats strfmt.Registry) error {

	if swag.IsZero(m.ApprovalStatus) { // not required
		return nil
	}

	// value enum
	if err := m.validateApprovalStatusEnum("ApprovalStatus", "body", m.ApprovalStatus); err != nil {
		return err
	}

	return nil
}

func (m *HPCResource) validateAssociatedLEXISProject(formats strfmt.Registry) error {

	if swag.IsZero(m.AssociatedLEXISProject) { // not required
		return nil
	}

	if err := validate.FormatOf("AssociatedLEXISProject", "body", "uuid", m.AssociatedLEXISProject.String(), formats); err != nil {
		return err
	}

	return nil
}

var hPCResourceTypeHPCProviderPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["IT4I","LRZ","ICHEC"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		hPCResourceTypeHPCProviderPropEnum = append(hPCResourceTypeHPCProviderPropEnum, v)
	}
}

const (

	// HPCResourceHPCProviderIT4I captures enum value "IT4I"
	HPCResourceHPCProviderIT4I string = "IT4I"

	// HPCResourceHPCProviderLRZ captures enum value "LRZ"
	HPCResourceHPCProviderLRZ string = "LRZ"

	// HPCResourceHPCProviderICHEC captures enum value "ICHEC"
	HPCResourceHPCProviderICHEC string = "ICHEC"
)

// prop value enum
func (m *HPCResource) validateHPCProviderEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, hPCResourceTypeHPCProviderPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *HPCResource) validateHPCProvider(formats strfmt.Registry) error {

	if swag.IsZero(m.HPCProvider) { // not required
		return nil
	}

	// value enum
	if err := m.validateHPCProviderEnum("HPCProvider", "body", m.HPCProvider); err != nil {
		return err
	}

	return nil
}

var hPCResourceTypeResourceTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CLOUD","HPC","SMARTGW"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		hPCResourceTypeResourceTypePropEnum = append(hPCResourceTypeResourceTypePropEnum, v)
	}
}

const (

	// HPCResourceResourceTypeCLOUD captures enum value "CLOUD"
	HPCResourceResourceTypeCLOUD string = "CLOUD"

	// HPCResourceResourceTypeHPC captures enum value "HPC"
	HPCResourceResourceTypeHPC string = "HPC"

	// HPCResourceResourceTypeSMARTGW captures enum value "SMARTGW"
	HPCResourceResourceTypeSMARTGW string = "SMARTGW"
)

// prop value enum
func (m *HPCResource) validateResourceTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, hPCResourceTypeResourceTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *HPCResource) validateResourceType(formats strfmt.Registry) error {

	if swag.IsZero(m.ResourceType) { // not required
		return nil
	}

	// value enum
	if err := m.validateResourceTypeEnum("ResourceType", "body", m.ResourceType); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HPCResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HPCResource) UnmarshalBinary(b []byte) error {
	var res HPCResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
