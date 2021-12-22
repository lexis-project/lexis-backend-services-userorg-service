package userManager

import (
	"context"
	"fmt"
	"time"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/user_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/statusManager"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

const (
	statusDuplicated = iota
	statusFail
	statusMissing
	statusOK
	statusForbidden
)

// UserManager is the struct defined to group and contain all the methods
// that interact with the user endpoint.
// Parameters:
// - db: a DbParameter reference to be able to use the DBManager methods.
// - BasePath: a string with the base path of the system.
type UserManager struct {
	db       *dbManager.DbParameter
	monit    *statusManager.StatusManager
	BasePath string
}

// New is the function to create the struct UserManager that grant access to
// the methods to interact with the User endpoint.
// Parameters:
// - db: a reference to the DbParameter to be able to interact with the db methods.
// - bp: a string containing the base path of the service.
// Returns:
// - UserManager: struct to interact with user endpoint functionalities.
func New(db *dbManager.DbParameter, monit *statusManager.StatusManager, bp string) *UserManager {

	monit.InitEndpoint("user")

	return &UserManager{
		db:       db,
		monit:    monit,
		BasePath: bp,
	}

}

// CreateUser (Swagger func) is the function behind the (POST) API Endpoint
// /user
// Its function is to create a new user with the model provided.
func (m *UserManager) CreateUser(ctx context.Context, params user_management.CreateUserParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("user", callTime)

	user := *params.User
	user.AllowedOrganizations = nil
	user.Projects = nil

	i, s, e := m.db.AddUser(ctx, user)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewCreateUserForbidden().WithPayload(&rValue)

	case statusDuplicated:

		rValue := models.ConflictResponse{
			Message: "The User already exists in the system.",
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewCreateUserConflict().WithPayload(&rValue)

	case statusOK:

		rValue := models.CreatedResponse{
			ID:   i.String(),
			Link: m.BasePath + "/user/" + i.String(),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewCreateUserCreated().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewCreateUserInternalServerError().WithPayload(&rValue)

	}

}

// DeleteUser (Swagger func) is the function behind the (DELETE) API Endpoint
// /user/{id}
// Its function is to delete the information that the system has about the
// user whose ID is provided.
func (m *UserManager) DeleteUser(ctx context.Context, params user_management.DeleteUserParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("user", callTime)

	s, e := m.db.DeleteUser(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewDeleteUserForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The User couldn't be found in the system.",
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewDeleteUserNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.DeletedResponse{
			ID:      (string)(params.ID),
			Message: "The User was deleted from the system.",
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewDeleteUserOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewDeleteUserInternalServerError().WithPayload(&rValue)

	}

}

// GetUser (Swagger func) is the function behind the (GET) API Endpoint
// /user
// Its function is to retrieve the information that the system has about the
// user whose ID is provided.
func (m *UserManager) GetUser(ctx context.Context, params user_management.GetUserParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("user", callTime)

	perm := false

	if params.Permissions != nil {

		perm = *params.Permissions

	}

	u, s, e := m.db.GetUser(ctx, params.ID, perm)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewGetUserForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The User couldn't be found in the system.",
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewGetUserNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("user", callTime)

		return user_management.NewGetUserOK().WithPayload(u)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewGetUserInternalServerError().WithPayload(&rValue)

	}

}

// ListUsers (Swagger func) is the function behind the (GET) API Endpoint
// /user/{id}
// Its function is to provide a list containing all the user in the system.
func (m *UserManager) ListUsers(ctx context.Context, params user_management.ListUsersParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("user", callTime)

	var email strfmt.Email
	var project string

	perm := false

	if params.Permissions != nil {

		perm = *params.Permissions

	}

	if params.Email != nil {

		email = *params.Email

	}

	if params.Project != nil {

		project = params.Project.String()

	}

	l, s, e := m.db.ListUsers(ctx, email, project, perm, *params.Scope)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewListUsersForbidden().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("user", callTime)

		return user_management.NewListUsersOK().WithPayload(l)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewListUsersInternalServerError().WithPayload(&rValue)

	}

}

// UpdateUser (Swagger func) is the function behind the (PUT) API Endpoint
// /user/{id}
// Its function is to update the user whose ID is provided with the new data.
func (m *UserManager) UpdateUser(ctx context.Context, params user_management.UpdateUserParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("user", callTime)

	user := params.User
	user.ID = params.ID
	user.AllowedOrganizations = nil
	user.Projects = nil

	u, s, e := m.db.UpdateUser(ctx, *user)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewUpdateUserForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The User couldn't be found in the system.",
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewUpdateUserNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("user", callTime)

		return user_management.NewUpdateUserOK().WithPayload(u)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("user", callTime)

		return user_management.NewUpdateUserInternalServerError().WithPayload(&rValue)

	}

}
