package accessManager

import (
	"context"
	"strings"
	"time"

	kclib "code.it4i.cz/lexis/wp4/keycloak-lib"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/access_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/statusManager"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	l "gitlab.com/cyclops-utilities/logging"
)

const (
	statusDuplicated = iota
	statusFail
	statusMissing
	statusOK
	statusForbidden
	SEC_API_KEY = "KEY"
	SEC_ORG     = "ORG"
	SEC_PRJ     = "PRJ"
	SEC_ROLE    = "ROLE"
	SEC_USER    = "USER"
	SEC_TOKEN   = "TOKEN"
	SEC_NAME    = "SHORTNAME"
	NIL         = "00000000-0000-0000-0000-000000000000"
)

// AccessManager is the struct defined to group and contain all the methods
// that interact with the user endpoint.
// Parameters:
// - db: a DbParameter reference to be able to use the DBManager methods.
// - BasePath: a string with the base path of the system.
type AccessManager struct {
	db       *dbManager.DbParameter
	monit    *statusManager.StatusManager
	BasePath string
}

// New is the function to create the struct AccessManager that grant access to
// the methods to interact with the User endpoint.
// Parameters:
// - db: a reference to the DbParameter to be able to interact with the db methods.
// - bp: a string containing the base path of the service.
// Returns:
// - AccessManager: struct to interact with user endpoint functionalities.
func New(db *dbManager.DbParameter, monit *statusManager.StatusManager, bp string) *AccessManager {

	monit.InitEndpoint("access")

	return &AccessManager{
		db:       db,
		monit:    monit,
		BasePath: bp,
	}

}

// AddRole (Swagger func) is the function behind the (POST) API Endpoint
// /authz/{UserID}/add/role
// Its function is to add the new role to the provided user..
func (m *AccessManager) AddRole(ctx context.Context, params access_management.AddRoleParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("access", callTime)

	var projectID strfmt.UUID
	var projectSN string

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	if !strings.Contains(authzData["IAM_WRITE"], params.OrganizationID.String()) {

		l.Warning.Printf("[ACCESS] Provided OrganizationID doesn't match any linked to the user with enough permissions.\n")

		rValue := models.ErrorResponse{
			Message: "Provided OrganizationID doesn't match any linked to the user with enough permissions",
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewAddRoleForbidden().WithPayload(&rValue)

	}

	if params.ProjectID != nil {

		projectID = *params.ProjectID

		if !strings.Contains(authzData["PRJ_WRITE"], projectID.String()) {

			l.Warning.Printf("[ACCESS] Provided ProjectID doesn't match any linked to the user with enough permissions.\n")

			rValue := models.ErrorResponse{
				Message: "Provided ProjectID doesn't match any linked to the user with enough permissions",
			}

			m.monit.APIHitDone("access", callTime)

			return access_management.NewAddRoleForbidden().WithPayload(&rValue)

		}

	}

	if params.ProjectShortName != nil {

		projectSN = *params.ProjectShortName

	}

	_, s, err := m.db.GetUser(ctx, params.UserID, false)

	switch s {

	case statusMissing:

		l.Warning.Printf("[ACCESS] The user doesn't exists or it's not related to your organization.\n")

		rValue := models.MissingResponse{
			Message: "The user couldn't be found",
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewAddRoleNotFound().WithPayload(&rValue)

	case statusFail:

		l.Warning.Printf("[ACCESS] Failed when getting the user.\n")

		rValue := models.ErrorResponse{
			Message: "Something went wrong. Error: " + err.Error(),
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewAddRoleInternalServerError().WithPayload(&rValue)

	case statusForbidden:

		l.Warning.Printf("[ACCESS] The user it's not related to your organization.\n")

		rValue := models.ErrorResponse{
			Message: "The user doesn't exists or it's not related to your organization. Error: " + err.Error(),
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewAddRoleForbidden().WithPayload(&rValue)

	}

	response, token := kclib.GetToken()

	if token != "" {

		_, perms := kclib.GetPermissionsFromRole(params.Role, params.OrganizationID.String(), projectSN, projectID.String())
		statusORG := kclib.AddUserToOrg(token, params.UserID.String(), params.OrganizationID.String(), perms)

		if statusORG.IsSuccess() {

			l.Info.Printf("[ACCESS] User [ %v ] added successfully to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, params.OrganizationID, statusORG.StatusCode, statusORG.Message)

			if projectID.String() != "" {

				_, perms := kclib.GetPermissionsFromRole(params.Role, params.OrganizationID.String(), projectSN, projectID.String())
				statusPRJ := kclib.AddUserToProject(token, params.UserID.String(), projectID.String(), params.OrganizationID.String(), perms)

				if statusPRJ.IsSuccess() {

					l.Info.Printf("[ACCESS] User [ %v ] added successfully to Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, projectID, statusPRJ.StatusCode, statusPRJ.Message)

				} else {

					l.Warning.Printf("[ACCESS] User [ %v ] couldn't be added to Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, projectID, statusPRJ.StatusCode, statusPRJ.Message)

					rValue := models.ErrorResponse{
						Message: "Keycloak-lib error: " + statusPRJ.Message,
					}

					m.monit.APIHitDone("access", callTime)

					return access_management.NewAddRoleInternalServerError().WithPayload(&rValue)

				}

			}

		} else {

			l.Warning.Printf("[ACCESS] User [ %v ] couldn't be added to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, params.OrganizationID, statusORG.StatusCode, statusORG.Message)

			rValue := models.ErrorResponse{
				Message: "Keycloak-lib error: " + statusORG.Message,
			}

			m.monit.APIHitDone("access", callTime)

			return access_management.NewAddRoleInternalServerError().WithPayload(&rValue)

		}

	} else {

		l.Warning.Printf("[ACCESS] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

		rValue := models.ErrorResponse{
			Message: "Keycloak-lib error: " + response.Message,
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewAddRoleInternalServerError().WithPayload(&rValue)

	}

	rValue := models.RoleAdded{
		Message: "Role added successfully to the user",
	}

	m.monit.APIHitDone("access", callTime)

	return access_management.NewAddRoleOK().WithPayload(&rValue)

}

// ClearRole (Swagger func) is the function behind the (POST) API Endpoint
// /authz/{UserID}/clear
// Its function is to clear the role of the provided user..
func (m *AccessManager) ClearRole(ctx context.Context, params access_management.ClearRoleParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("access", callTime)

	var projectID strfmt.UUID
	var projectSN string

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	if !strings.Contains(authzData["IAM_WRITE"], params.OrganizationID.String()) {

		l.Warning.Printf("[ACCESS] Provided OrganizationID doesn't match any linked to the user with enough permissions.\n")

		rValue := models.ErrorResponse{
			Message: "Provided OrganizationID doesn't match any linked to the user with enough permissions",
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewClearRoleForbidden().WithPayload(&rValue)

	}

	if params.ProjectID != nil {

		projectID = *params.ProjectID

		if !strings.Contains(authzData["PRJ_WRITE"], projectID.String()) {

			l.Warning.Printf("[ACCESS] Provided ProjectID doesn't match any linked to the user with enough permissions.\n")

			rValue := models.ErrorResponse{
				Message: "Provided ProjectID doesn't match any linked to the user with enough permissions",
			}

			m.monit.APIHitDone("access", callTime)

			return access_management.NewClearRoleForbidden().WithPayload(&rValue)

		}

	}

	if params.ProjectShortName != nil {

		projectSN = *params.ProjectShortName

	}

	_, s, err := m.db.GetUser(ctx, params.UserID, false)

	switch s {

	case statusMissing:

		l.Warning.Printf("[ACCESS] The user doesn't exists or it's not related to your organization.\n")

		rValue := models.MissingResponse{
			Message: "The user couldn't be found",
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewClearRoleNotFound().WithPayload(&rValue)

	case statusFail:

		l.Warning.Printf("[ACCESS] Failed when getting the user.\n")

		rValue := models.ErrorResponse{
			Message: "Something went wrong. Error: " + err.Error(),
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewClearRoleInternalServerError().WithPayload(&rValue)

	case statusForbidden:

		l.Warning.Printf("[ACCESS] The user it's not related to your organization.\n")

		rValue := models.ErrorResponse{
			Message: "The user doesn't exists or it's not related to your organization. Error: " + err.Error(),
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewClearRoleForbidden().WithPayload(&rValue)

	}

	response, token := kclib.GetToken()

	if token != "" {

		statusORG := kclib.DeleteUserFromOrg(token, params.UserID.String(), params.OrganizationID.String())

		if statusORG.IsSuccess() {

			l.Info.Printf("[ACCESS] User [ %v ] removed successfully from Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, params.OrganizationID, statusORG.StatusCode, statusORG.Message)

			if projectID.String() != "" {

				statusPRJ := kclib.DeleteUserFromProject(token, params.UserID.String(), projectID.String())

				if statusPRJ.IsSuccess() {

					l.Info.Printf("[ACCESS] User [ %v ] removed successfully from Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, projectID, statusPRJ.StatusCode, statusPRJ.Message)

				} else {

					l.Warning.Printf("[ACCESS] User [ %v ] couldn't be removed from Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, projectID, statusPRJ.StatusCode, statusPRJ.Message)

					rValue := models.ErrorResponse{
						Message: "Keycloak-lib error: " + statusPRJ.Message,
					}

					m.monit.APIHitDone("access", callTime)

					return access_management.NewClearRoleInternalServerError().WithPayload(&rValue)

				}

			}

		} else {

			l.Warning.Printf("[ACCESS] User [ %v ] couldn't be removed from Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", params.UserID, params.OrganizationID, statusORG.StatusCode, statusORG.Message)

			rValue := models.ErrorResponse{
				Message: "Keycloak-lib error: " + statusORG.Message,
			}

			m.monit.APIHitDone("access", callTime)

			return access_management.NewClearRoleInternalServerError().WithPayload(&rValue)

		}

	} else {

		l.Warning.Printf("[ACCESS] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

		rValue := models.ErrorResponse{
			Message: "Keycloak-lib error: " + response.Message,
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewClearRoleInternalServerError().WithPayload(&rValue)

	}

	_, perms := kclib.GetPermissionsFromRole("end_usr", params.OrganizationID.String(), projectSN, projectID.String())
	status := kclib.AddUserToOrg(token, params.UserID.String(), params.OrganizationID.String(), perms)

	if status.IsSuccess() {

		l.Info.Printf("[ACCESS] User [ %v ] added successfully to Organization [ %v ] in Keycloak as an end_usr: [ %v ] - [ %v ]\n", params.UserID, params.OrganizationID, status.StatusCode, status.Message)

		rValue := models.RoleAdded{
			Message: "Role added successfully to the user",
		}

		m.monit.APIHitDone("access", callTime)

		return access_management.NewClearRoleOK().WithPayload(&rValue)

	}

	l.Warning.Printf("[ACCESS] User [ %v ] couldn't be added to Organization [ %v ] in Keycloak as end_usr: [ %v ] - [ %v ]\n", params.UserID, projectID, status.StatusCode, status.Message)

	rValue := models.ErrorResponse{
		Message: "Keycloak-lib error: " + status.Message,
	}

	m.monit.APIHitDone("access", callTime)

	return access_management.NewClearRoleInternalServerError().WithPayload(&rValue)

}
