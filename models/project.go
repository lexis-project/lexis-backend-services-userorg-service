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
	"github.com/lib/pq"
)

// Project project
//
// swagger:model Project
type Project struct {

	// allowed organizations
	AllowedOrganizations pq.StringArray `json:"AllowedOrganizations,omitempty" gorm:"column:allowedorganizations;type:text[]"`

	// linked organization
	// Format: uuid
	LinkedOrganization strfmt.UUID `json:"LinkedOrganization,omitempty" gorm:"column:linkedorganization;type:uuid"`

	// norm core hours
	NormCoreHours *int64 `json:"NormCoreHours,omitempty" gorm:"column:normcorehours;default:0"`

	// project contact email
	// Format: email
	ProjectContactEmail strfmt.Email `json:"ProjectContactEmail,omitempty" gorm:"column:projectcontactemail"`

	// project contact person
	// Format: uuid
	ProjectContactPerson strfmt.UUID `json:"ProjectContactPerson,omitempty" gorm:"column:projectcontactperson;type:uuid"`

	// project created by
	// Format: uuid
	ProjectCreatedBy strfmt.UUID `json:"ProjectCreatedBy,omitempty" gorm:"column:projectcreatedby;type:uuid"`

	// project creation time
	// Format: date-time
	ProjectCreationTime strfmt.DateTime `json:"ProjectCreationTime,omitempty" gorm:"column:projectcreationtime;type:timestamptz;default:now()"`

	// project description
	ProjectDescription string `json:"ProjectDescription,omitempty" gorm:"column:projectdescription"`

	// project domain
	ProjectDomain string `json:"ProjectDomain,omitempty" gorm:"column:projectdomain"`

	// project ID
	// Format: uuid
	ProjectID strfmt.UUID `json:"ProjectID,omitempty" gorm:"column:projectid;type:uuid;primary_key;unique;default:md5(random()::text || clock_timestamp()::text)::uuid"`

	// project max price
	ProjectMaxPrice *float64 `json:"ProjectMaxPrice,omitempty" gorm:"column:projectmaxprice;type:float8;default:0.0"`

	// project name
	ProjectName string `json:"ProjectName,omitempty" gorm:"column:projectname"`

	// project short name
	ProjectShortName string `json:"ProjectShortName,omitempty" gorm:"column:projectshortname;unique"`

	// project start date
	// Format: date-time
	ProjectStartDate strfmt.DateTime `json:"ProjectStartDate,omitempty" gorm:"column:projectstartdate;type:timestamptz"`

	// project status
	// Enum: [PENDING ACTIVE DISABLED TERMINATED]
	ProjectStatus string `json:"ProjectStatus,omitempty" gorm:"column:projectstatus"`

	// project termination date
	// Format: date-time
	ProjectTerminationDate strfmt.DateTime `json:"ProjectTerminationDate,omitempty" gorm:"column:projectterminationdate;type:timestamptz"`
}

// Validate validates this project
func (m *Project) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinkedOrganization(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectContactEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectContactPerson(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectCreatedBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectCreationTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectStartDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProjectTerminationDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Project) validateLinkedOrganization(formats strfmt.Registry) error {

	if swag.IsZero(m.LinkedOrganization) { // not required
		return nil
	}

	if err := validate.FormatOf("LinkedOrganization", "body", "uuid", m.LinkedOrganization.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectContactEmail(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectContactEmail) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectContactEmail", "body", "email", m.ProjectContactEmail.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectContactPerson(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectContactPerson) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectContactPerson", "body", "uuid", m.ProjectContactPerson.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectCreatedBy(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectCreatedBy) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectCreatedBy", "body", "uuid", m.ProjectCreatedBy.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectCreationTime(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectCreationTime) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectCreationTime", "body", "date-time", m.ProjectCreationTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectID(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectID) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectID", "body", "uuid", m.ProjectID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectStartDate(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectStartDate) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectStartDate", "body", "date-time", m.ProjectStartDate.String(), formats); err != nil {
		return err
	}

	return nil
}

var projectTypeProjectStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["PENDING","ACTIVE","DISABLED","TERMINATED"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		projectTypeProjectStatusPropEnum = append(projectTypeProjectStatusPropEnum, v)
	}
}

const (

	// ProjectProjectStatusPENDING captures enum value "PENDING"
	ProjectProjectStatusPENDING string = "PENDING"

	// ProjectProjectStatusACTIVE captures enum value "ACTIVE"
	ProjectProjectStatusACTIVE string = "ACTIVE"

	// ProjectProjectStatusDISABLED captures enum value "DISABLED"
	ProjectProjectStatusDISABLED string = "DISABLED"

	// ProjectProjectStatusTERMINATED captures enum value "TERMINATED"
	ProjectProjectStatusTERMINATED string = "TERMINATED"
)

// prop value enum
func (m *Project) validateProjectStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, projectTypeProjectStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Project) validateProjectStatus(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectStatus) { // not required
		return nil
	}

	// value enum
	if err := m.validateProjectStatusEnum("ProjectStatus", "body", m.ProjectStatus); err != nil {
		return err
	}

	return nil
}

func (m *Project) validateProjectTerminationDate(formats strfmt.Registry) error {

	if swag.IsZero(m.ProjectTerminationDate) { // not required
		return nil
	}

	if err := validate.FormatOf("ProjectTerminationDate", "body", "date-time", m.ProjectTerminationDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Project) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Project) UnmarshalBinary(b []byte) error {
	var res Project
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
