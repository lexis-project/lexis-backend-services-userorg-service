// Code generated by go-swagger; DO NOT EDIT.

package project_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetProjectHandlerFunc turns a function with the right signature into a get project handler
type GetProjectHandlerFunc func(GetProjectParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetProjectHandlerFunc) Handle(params GetProjectParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetProjectHandler interface for that can handle valid get project params
type GetProjectHandler interface {
	Handle(GetProjectParams, interface{}) middleware.Responder
}

// NewGetProject creates a new http.Handler for the get project operation
func NewGetProject(ctx *middleware.Context, handler GetProjectHandler) *GetProject {
	return &GetProject{Context: ctx, Handler: handler}
}

/*GetProject swagger:route GET /project/{id} projectManagement getProject

Get specific project

get project with given id

*/
type GetProject struct {
	Context *middleware.Context
	Handler GetProjectHandler
}

func (o *GetProject) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetProjectParams()

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
