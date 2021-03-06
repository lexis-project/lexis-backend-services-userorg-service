// Code generated by go-swagger; DO NOT EDIT.

package access_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

//go:generate mockery -name API -inpkg

// API is the interface of the access management client
type API interface {
	/*
	   AddRole adds a role to the specified user

	   It adds a role to the user*/
	AddRole(ctx context.Context, params *AddRoleParams) (*AddRoleOK, error)
	/*
	   ClearRole clears the actual role of the user and assignes a end user one

	   It clears the actual role of the user and assignes a end_user one*/
	ClearRole(ctx context.Context, params *ClearRoleParams) (*ClearRoleOK, error)
}

// New creates a new access management API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry, authInfo runtime.ClientAuthInfoWriter) *Client {
	return &Client{
		transport: transport,
		formats:   formats,
		authInfo:  authInfo,
	}
}

/*
Client for access management API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
	authInfo  runtime.ClientAuthInfoWriter
}

/*
AddRole adds a role to the specified user

It adds a role to the user
*/
func (a *Client) AddRole(ctx context.Context, params *AddRoleParams) (*AddRoleOK, error) {

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "addRole",
		Method:             "POST",
		PathPattern:        "/authz/{userID}/add/{role}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &AddRoleReader{formats: a.formats},
		AuthInfo:           a.authInfo,
		Context:            ctx,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*AddRoleOK), nil

}

/*
ClearRole clears the actual role of the user and assignes a end user one

It clears the actual role of the user and assignes a end_user one
*/
func (a *Client) ClearRole(ctx context.Context, params *ClearRoleParams) (*ClearRoleOK, error) {

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "clearRole",
		Method:             "POST",
		PathPattern:        "/authz/{userID}/clear",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &ClearRoleReader{formats: a.formats},
		AuthInfo:           a.authInfo,
		Context:            ctx,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*ClearRoleOK), nil

}
