// Code generated by go-swagger; DO NOT EDIT.

package organization_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// CreateOrganizationHandlerFunc turns a function with the right signature into a create organization handler
type CreateOrganizationHandlerFunc func(CreateOrganizationParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn CreateOrganizationHandlerFunc) Handle(params CreateOrganizationParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// CreateOrganizationHandler interface for that can handle valid create organization params
type CreateOrganizationHandler interface {
	Handle(CreateOrganizationParams, interface{}) middleware.Responder
}

// NewCreateOrganization creates a new http.Handler for the create organization operation
func NewCreateOrganization(ctx *middleware.Context, handler CreateOrganizationHandler) *CreateOrganization {
	return &CreateOrganization{Context: ctx, Handler: handler}
}

/*CreateOrganization swagger:route POST /organization organizationManagement createOrganization

create Organization

Creates a new organization

*/
type CreateOrganization struct {
	Context *middleware.Context
	Handler CreateOrganizationHandler
}

func (o *CreateOrganization) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewCreateOrganizationParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
