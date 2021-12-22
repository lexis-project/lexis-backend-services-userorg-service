package projectManager

import (
	"context"
	"fmt"
	"time"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/project_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/statusManager"
	"github.com/go-openapi/runtime/middleware"
)

const (
	statusDuplicated = iota
	statusFail
	statusMissing
	statusOK
	statusForbidden
)

// ProjectManager is the struct defined to group and contain all the methods
// that interact with the project endpoint.
// Parameters:
// - db: a DbParameter reference to be able to use the DBManager methods.
// - BasePath: a string with the base path of the system.
type ProjectManager struct {
	db       *dbManager.DbParameter
	monit    *statusManager.StatusManager
	BasePath string
}

// New is the function to create the struct ProjectManager that grant access
// to the methods to interact with the Project endpoint.
// Parameters:
// - db: a reference to the DbParameter to be able to interact with the db methods.
// - bp: a string containing the base path of the service.
// Returns:
// - ProjectManager: struct to interact with project endpoint functionalities.
func New(db *dbManager.DbParameter, monit *statusManager.StatusManager, bp string) *ProjectManager {

	monit.InitEndpoint("project")

	return &ProjectManager{
		db:       db,
		monit:    monit,
		BasePath: bp,
	}

}

// CreateProject (Swagger func) is the function behind the (POST) API Endpoint
// /project
// Its function is to create a new project with the model provided.
func (m *ProjectManager) CreateProject(ctx context.Context, params project_management.CreateProjectParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	available, e := m.db.IsShortNameAvailable(ctx, params.Project.ProjectShortName)

	if !available {

		rValue := models.ErrorResponse{
			Message: "INVALID_PROJECT_SHORT_NAME",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewCreateProjectUnprocessableEntity().WithPayload(&rValue)
	}

	if e != nil {

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewCreateProjectInternalServerError().WithPayload(&rValue)

	}

	i, s, e := m.db.AddProject(ctx, *params.Project)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewCreateProjectForbidden().WithPayload(&rValue)

	case statusDuplicated:

		rValue := models.ConflictResponse{
			Message: "The project already exists in the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewCreateProjectConflict().WithPayload(&rValue)

	case statusOK:

		rValue := models.CreatedResponse{
			ID:   i.String(),
			Link: m.BasePath + "/project/" + i.String(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewCreateProjectCreated().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewCreateProjectInternalServerError().WithPayload(&rValue)

	}

}

// DeleteProject (Swagger func) is the function behind the (DELETE) API Endpoint
// /project/{id}
// Its function is to delete the information that the system has about the
// project whose ID is provided.
func (m *ProjectManager) DeleteProject(ctx context.Context, params project_management.DeleteProjectParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	s, e := m.db.DeleteProject(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteProjectForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Project couldn't be found in the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteProjectNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.DeletedResponse{
			ID:      (string)(params.ID),
			Message: "The Project was deleted from the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteProjectOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteProjectInternalServerError().WithPayload(&rValue)

	}

}

// GetProject (Swagger func) is the function behind the (GET) API Endpoint
// /project
// Its function is to retrieve the information that the system has about the
// project whose ID is provided.
func (m *ProjectManager) GetProject(ctx context.Context, params project_management.GetProjectParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	p, s, e := m.db.GetProject(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewGetProjectForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Project couldn't be found in the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewGetProjectNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("project", callTime)

		return project_management.NewGetProjectOK().WithPayload(p)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewGetProjectInternalServerError().WithPayload(&rValue)

	}

}

// ListProjects (Swagger func) is the function behind the (GET) API Endpoint
// /project/{id}
// Its function is to provide a list containing all the project in the system.
func (m *ProjectManager) ListProjects(ctx context.Context, params project_management.ListProjectsParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	l, s, e := m.db.ListProjects(ctx, *params.Scope)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewListProjectsForbidden().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("project", callTime)

		return project_management.NewListProjectsOK().WithPayload(l)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewListProjectsInternalServerError().WithPayload(&rValue)

	}

}

// UpdateProject (Swagger func) is the function behind the (PUT) API Endpoint
// /project/{id}
// Its function is to update the project whose ID is provided with the new data.
func (m *ProjectManager) UpdateProject(ctx context.Context, params project_management.UpdateProjectParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	project := params.Project
	project.ProjectID = params.ID
	project.AllowedOrganizations = nil

	if project.ProjectShortName != "" {

		available, e := m.db.IsShortNameAvailable(ctx, project.ProjectShortName)

		if !available {

			rValue := models.ErrorResponse{
				Message: "INVALID_PROJECT_SHORT_NAME",
			}

			m.monit.APIHitDone("project", callTime)

			return project_management.NewUpdateProjectUnprocessableEntity().WithPayload(&rValue)
		}

		if e != nil {

			rValue := models.ErrorResponse{
				Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
			}

			m.monit.APIHitDone("project", callTime)

			return project_management.NewUpdateProjectInternalServerError().WithPayload(&rValue)

		}

	}

	p, s, e := m.db.UpdateProject(ctx, *project)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewUpdateProjectForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Project couldn't be found in the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewUpdateProjectNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("project", callTime)

		return project_management.NewUpdateProjectOK().WithPayload(p)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewUpdateProjectInternalServerError().WithPayload(&rValue)

	}

}

func (m *ProjectManager) AddUserToProject(ctx context.Context, params project_management.AddUserToProjectParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	s, e := m.db.AddUserToPrj(ctx, params.UserID, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewAddUserToProjectForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Project/User couldn't be found in the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewAddUserToProjectNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.OKResponse{
			Message: "User updated successfully.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewAddUserToProjectOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewAddUserToProjectInternalServerError().WithPayload(&rValue)

	}

}

func (m *ProjectManager) DeleteUserFromProject(ctx context.Context, params project_management.DeleteUserFromProjectParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("project", callTime)

	s, e := m.db.DeleteUserFromPrj(ctx, params.UserID, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteUserFromProjectForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Project/User couldn't be found in the system.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteUserFromProjectNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.DeletedResponse{
			Message: "User updated successfully.",
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteUserFromProjectOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("project", callTime)

		return project_management.NewDeleteUserFromProjectInternalServerError().WithPayload(&rValue)

	}

}
