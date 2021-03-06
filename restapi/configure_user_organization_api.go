// Code generated by go-swagger; DO NOT EDIT.

package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/runtime/security"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/access_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/hpc_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/organization_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/project_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/status_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/user_management"
)

type contextKey string

const AuthKey contextKey = "Auth"

//go:generate mockery -name AccessManagementAPI -inpkg

/* AccessManagementAPI  */
type AccessManagementAPI interface {
	/* AddRole add a role to the specified user */
	AddRole(ctx context.Context, params access_management.AddRoleParams) middleware.Responder

	/* ClearRole clears the actual role of the user and assignes a end_user one */
	ClearRole(ctx context.Context, params access_management.ClearRoleParams) middleware.Responder
}

//go:generate mockery -name HpcManagementAPI -inpkg

/* HpcManagementAPI  */
type HpcManagementAPI interface {
	/* CreateHPCResource create HPCResource */
	CreateHPCResource(ctx context.Context, params hpc_management.CreateHPCResourceParams) middleware.Responder

	/* DeleteHPCResource Delete specific HPCResource */
	DeleteHPCResource(ctx context.Context, params hpc_management.DeleteHPCResourceParams) middleware.Responder

	/* GetHPCResource Get specific HPCResource */
	GetHPCResource(ctx context.Context, params hpc_management.GetHPCResourceParams) middleware.Responder

	/* ListHPCResources list HPCResource */
	ListHPCResources(ctx context.Context, params hpc_management.ListHPCResourcesParams) middleware.Responder

	/* UpdateHPCResource Update specific HPCResource */
	UpdateHPCResource(ctx context.Context, params hpc_management.UpdateHPCResourceParams) middleware.Responder
}

//go:generate mockery -name OrganizationManagementAPI -inpkg

/* OrganizationManagementAPI  */
type OrganizationManagementAPI interface {
	/* AddUserToOrganization Adds user to organization */
	AddUserToOrganization(ctx context.Context, params organization_management.AddUserToOrganizationParams) middleware.Responder

	/* CreateOrganization create Organization */
	CreateOrganization(ctx context.Context, params organization_management.CreateOrganizationParams) middleware.Responder

	/* DeleteOrganization Delete specific organization */
	DeleteOrganization(ctx context.Context, params organization_management.DeleteOrganizationParams) middleware.Responder

	/* DeleteUserFromOrganization Delete user from organization */
	DeleteUserFromOrganization(ctx context.Context, params organization_management.DeleteUserFromOrganizationParams) middleware.Responder

	/* GetOrganization Get specific organization */
	GetOrganization(ctx context.Context, params organization_management.GetOrganizationParams) middleware.Responder

	/* ListOrganizations list organizations */
	ListOrganizations(ctx context.Context, params organization_management.ListOrganizationsParams) middleware.Responder

	/* UpdateOrganization Update specific organization */
	UpdateOrganization(ctx context.Context, params organization_management.UpdateOrganizationParams) middleware.Responder
}

//go:generate mockery -name ProjectManagementAPI -inpkg

/* ProjectManagementAPI  */
type ProjectManagementAPI interface {
	/* AddUserToProject Add user to project */
	AddUserToProject(ctx context.Context, params project_management.AddUserToProjectParams) middleware.Responder

	/* CreateProject create Project */
	CreateProject(ctx context.Context, params project_management.CreateProjectParams) middleware.Responder

	/* DeleteProject Delete specific project */
	DeleteProject(ctx context.Context, params project_management.DeleteProjectParams) middleware.Responder

	/* DeleteUserFromProject Delete user from project */
	DeleteUserFromProject(ctx context.Context, params project_management.DeleteUserFromProjectParams) middleware.Responder

	/* GetProject Get specific project */
	GetProject(ctx context.Context, params project_management.GetProjectParams) middleware.Responder

	/* ListProjects list projects */
	ListProjects(ctx context.Context, params project_management.ListProjectsParams) middleware.Responder

	/* UpdateProject Update specific project */
	UpdateProject(ctx context.Context, params project_management.UpdateProjectParams) middleware.Responder
}

//go:generate mockery -name StatusManagementAPI -inpkg

/* StatusManagementAPI  */
type StatusManagementAPI interface {
	/* GetStatus Basic status of the system */
	GetStatus(ctx context.Context, params status_management.GetStatusParams) middleware.Responder

	/* ShowStatus Basic status of the system */
	ShowStatus(ctx context.Context, params status_management.ShowStatusParams) middleware.Responder
}

//go:generate mockery -name UserManagementAPI -inpkg

/* UserManagementAPI  */
type UserManagementAPI interface {
	/* CreateUser Create a user */
	CreateUser(ctx context.Context, params user_management.CreateUserParams) middleware.Responder

	/* DeleteUser Delete specific user */
	DeleteUser(ctx context.Context, params user_management.DeleteUserParams) middleware.Responder

	/* GetUser Get specific user */
	GetUser(ctx context.Context, params user_management.GetUserParams) middleware.Responder

	/* ListUsers List all users */
	ListUsers(ctx context.Context, params user_management.ListUsersParams) middleware.Responder

	/* UpdateUser Update specific user */
	UpdateUser(ctx context.Context, params user_management.UpdateUserParams) middleware.Responder
}

// Config is configuration for Handler
type Config struct {
	AccessManagementAPI
	HpcManagementAPI
	OrganizationManagementAPI
	ProjectManagementAPI
	StatusManagementAPI
	UserManagementAPI
	Logger func(string, ...interface{})
	// InnerMiddleware is for the handler executors. These do not apply to the swagger.json document.
	// The middleware executes after routing but before authentication, binding and validation
	InnerMiddleware func(http.Handler) http.Handler

	// Authorizer is used to authorize a request after the Auth function was called using the "Auth*" functions
	// and the principal was stored in the context in the "AuthKey" context value.
	Authorizer func(*http.Request) error

	// AuthAPIKeyHeader Applies when the "X-API-KEY" header is set
	AuthAPIKeyHeader func(token string) (interface{}, error)

	// AuthAPIKeyParam Applies when the "api_key" query is set
	AuthAPIKeyParam func(token string) (interface{}, error)

	// AuthKeycloak For OAuth2 authentication
	AuthKeycloak func(token string, scopes []string) (interface{}, error)
	// Authenticator to use for all APIKey authentication
	APIKeyAuthenticator func(string, string, security.TokenAuthentication) runtime.Authenticator
	// Authenticator to use for all Bearer authentication
	BasicAuthenticator func(security.UserPassAuthentication) runtime.Authenticator
	// Authenticator to use for all Basic authentication
	BearerAuthenticator func(string, security.ScopedTokenAuthentication) runtime.Authenticator
}

// Handler returns an http.Handler given the handler configuration
// It mounts all the business logic implementers in the right routing.
func Handler(c Config) (http.Handler, error) {
	h, _, err := HandlerAPI(c)
	return h, err
}

// HandlerAPI returns an http.Handler given the handler configuration
// and the corresponding *UserOrganizationAPI instance.
// It mounts all the business logic implementers in the right routing.
func HandlerAPI(c Config) (http.Handler, *operations.UserOrganizationAPIAPI, error) {
	spec, err := loads.Analyzed(swaggerCopy(SwaggerJSON), "")
	if err != nil {
		return nil, nil, fmt.Errorf("analyze swagger: %v", err)
	}
	api := operations.NewUserOrganizationAPIAPI(spec)
	api.ServeError = errors.ServeError
	api.Logger = c.Logger

	if c.APIKeyAuthenticator != nil {
		api.APIKeyAuthenticator = c.APIKeyAuthenticator
	}
	if c.BasicAuthenticator != nil {
		api.BasicAuthenticator = c.BasicAuthenticator
	}
	if c.BearerAuthenticator != nil {
		api.BearerAuthenticator = c.BearerAuthenticator
	}

	api.JSONConsumer = runtime.JSONConsumer()
	api.JSONProducer = runtime.JSONProducer()
	api.APIKeyHeaderAuth = func(token string) (interface{}, error) {
		if c.AuthAPIKeyHeader == nil {
			return token, nil
		}
		return c.AuthAPIKeyHeader(token)
	}

	api.APIKeyParamAuth = func(token string) (interface{}, error) {
		if c.AuthAPIKeyParam == nil {
			return token, nil
		}
		return c.AuthAPIKeyParam(token)
	}

	api.KeycloakAuth = func(token string, scopes []string) (interface{}, error) {
		if c.AuthKeycloak == nil {
			return token, nil
		}
		return c.AuthKeycloak(token, scopes)
	}
	api.APIAuthorizer = authorizer(c.Authorizer)
	api.AccessManagementAddRoleHandler = access_management.AddRoleHandlerFunc(func(params access_management.AddRoleParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.AccessManagementAPI.AddRole(ctx, params)
	})
	api.OrganizationManagementAddUserToOrganizationHandler = organization_management.AddUserToOrganizationHandlerFunc(func(params organization_management.AddUserToOrganizationParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.AddUserToOrganization(ctx, params)
	})
	api.ProjectManagementAddUserToProjectHandler = project_management.AddUserToProjectHandlerFunc(func(params project_management.AddUserToProjectParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.AddUserToProject(ctx, params)
	})
	api.AccessManagementClearRoleHandler = access_management.ClearRoleHandlerFunc(func(params access_management.ClearRoleParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.AccessManagementAPI.ClearRole(ctx, params)
	})
	api.HpcManagementCreateHPCResourceHandler = hpc_management.CreateHPCResourceHandlerFunc(func(params hpc_management.CreateHPCResourceParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.HpcManagementAPI.CreateHPCResource(ctx, params)
	})
	api.OrganizationManagementCreateOrganizationHandler = organization_management.CreateOrganizationHandlerFunc(func(params organization_management.CreateOrganizationParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.CreateOrganization(ctx, params)
	})
	api.ProjectManagementCreateProjectHandler = project_management.CreateProjectHandlerFunc(func(params project_management.CreateProjectParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.CreateProject(ctx, params)
	})
	api.UserManagementCreateUserHandler = user_management.CreateUserHandlerFunc(func(params user_management.CreateUserParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.UserManagementAPI.CreateUser(ctx, params)
	})
	api.HpcManagementDeleteHPCResourceHandler = hpc_management.DeleteHPCResourceHandlerFunc(func(params hpc_management.DeleteHPCResourceParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.HpcManagementAPI.DeleteHPCResource(ctx, params)
	})
	api.OrganizationManagementDeleteOrganizationHandler = organization_management.DeleteOrganizationHandlerFunc(func(params organization_management.DeleteOrganizationParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.DeleteOrganization(ctx, params)
	})
	api.ProjectManagementDeleteProjectHandler = project_management.DeleteProjectHandlerFunc(func(params project_management.DeleteProjectParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.DeleteProject(ctx, params)
	})
	api.UserManagementDeleteUserHandler = user_management.DeleteUserHandlerFunc(func(params user_management.DeleteUserParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.UserManagementAPI.DeleteUser(ctx, params)
	})
	api.OrganizationManagementDeleteUserFromOrganizationHandler = organization_management.DeleteUserFromOrganizationHandlerFunc(func(params organization_management.DeleteUserFromOrganizationParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.DeleteUserFromOrganization(ctx, params)
	})
	api.ProjectManagementDeleteUserFromProjectHandler = project_management.DeleteUserFromProjectHandlerFunc(func(params project_management.DeleteUserFromProjectParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.DeleteUserFromProject(ctx, params)
	})
	api.HpcManagementGetHPCResourceHandler = hpc_management.GetHPCResourceHandlerFunc(func(params hpc_management.GetHPCResourceParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.HpcManagementAPI.GetHPCResource(ctx, params)
	})
	api.OrganizationManagementGetOrganizationHandler = organization_management.GetOrganizationHandlerFunc(func(params organization_management.GetOrganizationParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.GetOrganization(ctx, params)
	})
	api.ProjectManagementGetProjectHandler = project_management.GetProjectHandlerFunc(func(params project_management.GetProjectParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.GetProject(ctx, params)
	})
	api.StatusManagementGetStatusHandler = status_management.GetStatusHandlerFunc(func(params status_management.GetStatusParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.StatusManagementAPI.GetStatus(ctx, params)
	})
	api.UserManagementGetUserHandler = user_management.GetUserHandlerFunc(func(params user_management.GetUserParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.UserManagementAPI.GetUser(ctx, params)
	})
	api.HpcManagementListHPCResourcesHandler = hpc_management.ListHPCResourcesHandlerFunc(func(params hpc_management.ListHPCResourcesParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.HpcManagementAPI.ListHPCResources(ctx, params)
	})
	api.OrganizationManagementListOrganizationsHandler = organization_management.ListOrganizationsHandlerFunc(func(params organization_management.ListOrganizationsParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.ListOrganizations(ctx, params)
	})
	api.ProjectManagementListProjectsHandler = project_management.ListProjectsHandlerFunc(func(params project_management.ListProjectsParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.ListProjects(ctx, params)
	})
	api.UserManagementListUsersHandler = user_management.ListUsersHandlerFunc(func(params user_management.ListUsersParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.UserManagementAPI.ListUsers(ctx, params)
	})
	api.StatusManagementShowStatusHandler = status_management.ShowStatusHandlerFunc(func(params status_management.ShowStatusParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.StatusManagementAPI.ShowStatus(ctx, params)
	})
	api.HpcManagementUpdateHPCResourceHandler = hpc_management.UpdateHPCResourceHandlerFunc(func(params hpc_management.UpdateHPCResourceParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.HpcManagementAPI.UpdateHPCResource(ctx, params)
	})
	api.OrganizationManagementUpdateOrganizationHandler = organization_management.UpdateOrganizationHandlerFunc(func(params organization_management.UpdateOrganizationParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.OrganizationManagementAPI.UpdateOrganization(ctx, params)
	})
	api.ProjectManagementUpdateProjectHandler = project_management.UpdateProjectHandlerFunc(func(params project_management.UpdateProjectParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.ProjectManagementAPI.UpdateProject(ctx, params)
	})
	api.UserManagementUpdateUserHandler = user_management.UpdateUserHandlerFunc(func(params user_management.UpdateUserParams, principal interface{}) middleware.Responder {
		ctx := params.HTTPRequest.Context()
		ctx = storeAuth(ctx, principal)
		return c.UserManagementAPI.UpdateUser(ctx, params)
	})
	api.ServerShutdown = func() {}
	return api.Serve(c.InnerMiddleware), api, nil
}

// swaggerCopy copies the swagger json to prevent data races in runtime
func swaggerCopy(orig json.RawMessage) json.RawMessage {
	c := make(json.RawMessage, len(orig))
	copy(c, orig)
	return c
}

// authorizer is a helper function to implement the runtime.Authorizer interface.
type authorizer func(*http.Request) error

func (a authorizer) Authorize(req *http.Request, principal interface{}) error {
	if a == nil {
		return nil
	}
	ctx := storeAuth(req.Context(), principal)
	return a(req.WithContext(ctx))
}

func storeAuth(ctx context.Context, principal interface{}) context.Context {
	return context.WithValue(ctx, AuthKey, principal)
}
