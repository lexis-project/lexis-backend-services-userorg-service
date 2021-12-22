package dbManager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	kclib "code.it4i.cz/lexis/wp4/keycloak-lib"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi"
	"github.com/Nerzal/gocloak/v9"
	"github.com/go-openapi/strfmt"
	"gitlab.com/cyclops-utilities/datamodels"
	l "gitlab.com/cyclops-utilities/logging"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

// DbParameter is the struct defined to group and contain all the methods
// that interact with the database.
//
// On it there is the following parameters:
// - connStr: strings with the connection information to the database
// - Db: a gorm.DB pointer to the db to invoke all the db methods
type DbParameter struct {
	connStr string
	Db      *gorm.DB
	k       KeycloakConfig
}

type KeycloakConfig struct {
	Enabled      bool   `json:"enabled"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Realm        string `json:"realm"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	UseHTTP      bool   `json:"use_http"`
	RedirectURL  string `json:"redirect_url"`
}

// New is the function to create the struct DbParameter.
// Parameters:
// - dbConn: strings with the connection information to the database
// - tables: array of interfaces that will contains the models to migrate
// to the database on initialization
// Returns:
// - DbParameter: struct to interact with dbManager functionalities
func New(c KeycloakConfig, dbConn string, tables ...interface{}) *DbParameter {

	var (
		dp  DbParameter
		err error
	)

	dp.connStr = dbConn
	dp.k = c

	dp.Db, err = gorm.Open(postgres.Open(dbConn), &gorm.Config{})

	if err != nil {

		l.Error.Printf("[DB] Error opening connection. Error: %v\n", err)

		panic(err)

	}

	dp.Db.AutoMigrate(tables...)

	return &dp

}

// getKeycloaktService returns the keycloak service; note that there has to be exceptional
// handling of port 80 and port 443
func (d *DbParameter) getKeycloakService() (s string) {

	if d.k.UseHTTP {

		s = "http://" + d.k.Host

		if d.k.Port != 80 {

			s = s + ":" + strconv.Itoa(d.k.Port)
		}

	} else {

		s = "https://" + d.k.Host

		if d.k.Port != 443 {

			s = s + ":" + strconv.Itoa(d.k.Port)

		}

	}

	return

}

func (d *DbParameter) getMatchingList(inField, anyField, own string, allowed []string) (in, any string) {

	var fullList []string

	if own != "" {

		fullList = append(fullList, own)

	}

	if len(allowed) > 0 {

		fullList = append(fullList, allowed...)

	}

	if len(fullList) > 0 {

		in = fmt.Sprintf("%v IN ('%v'", inField, fullList[0])
		any = fmt.Sprintf("'%v' = ANY(%v)", fullList[0], anyField)

		for i, v := range fullList {

			if i == 0 {

				continue

			}

			any = fmt.Sprintf("%v OR '%v' = ANY(%v)", any, v, anyField)

			in = fmt.Sprintf("%v,'%v'", in, v)

		}

		in = fmt.Sprintf("%v)", in)

	}

	return

}

// isUserAllowed checks against the authz information is the user is allowed
// to operate the endpoint.
func (d *DbParameter) isUserAllowed(org, prj, permission string, authz map[string]string) bool {

	if org == "" && prj == "" {

		return false

	}

	var probingkey string

	if org != "" && org != NIL {

		probingkey = org

	}

	if prj != "" && prj != NIL {

		probingkey = org + "/" + prj

	}

	authzCheck := authz[permission]

	return strings.Contains(authzCheck, probingkey) || strings.Contains(authzCheck, "*")

}

func (d *DbParameter) validDates(from, to strfmt.DateTime) bool {

	boundary := time.Now().Add(time.Minute * -60)

	f := (time.Time)(from)
	t := (time.Time)(to)

	if f.IsZero() || t.IsZero() {

		return false

	}

	if f.Before(boundary) || t.Before(boundary) {

		return false

	}

	if t.Before(f) {

		return false

	}

	return true

}

// getPermissions retrieves from keycloak the list of groups and their respectives
// associated permissions linked to the user whose ID is provided.
func (d *DbParameter) getPermissions(ctx context.Context, id string) (datamodels.JSONdb, error) {

	permissions := make(datamodels.JSONdb)

	client, token, _ := d.getKeycloakClient()

	tt := true

	groups, e := client.GetUserGroups(ctx, token.AccessToken, d.k.Realm, id, gocloak.GetGroupsParams{Full: &tt})

	if e != nil {

		l.Warning.Printf("[DB] [Keycloak] Error getting list of groups linked to the user. Error: %v", e)

		return nil, e

	}

	for _, group := range groups {

		groupInfo, e := client.GetGroup(ctx, token.AccessToken, d.k.Realm, *group.ID)

		if e != nil {

			l.Warning.Printf("[DB] [Keycloak] Error getting details of the groups linked to the user. Error: %v", e)

			return nil, e

		}

		for i, v := range *groupInfo.Attributes {

			index := strings.ToLower(i)

			if perm, exists := permissions[index]; exists {

				for _, att := range v {

					temp := fmt.Sprintf("%v", att)

					jsonMap := make(map[string]interface{})

					e := json.Unmarshal([]byte(temp), &jsonMap)

					if e != nil {

						l.Warning.Printf("[DB] Error unmarshalling values from Keycloak... Skipping... Error: %v", e)

					}

					permissions[index] = append(perm.([]map[string]interface{}), jsonMap)

				}

			} else {

				var tempSlice []map[string]interface{}

				for _, att := range v {

					temp := fmt.Sprintf("%v", att)

					jsonMap := make(map[string]interface{})

					e := json.Unmarshal([]byte(temp), &jsonMap)

					if e != nil {

						l.Warning.Printf("[DB] Error unmarshalling values from Keycloak... Skipping... Error: %v", e)

					}

					tempSlice = append(tempSlice, jsonMap)

				}

				permissions[index] = tempSlice

			}

		}

	}

	return permissions, nil

}

// getKeycloakClient provides the objects needed to connect to the keycloak
// instance using the proided config.
func (d *DbParameter) getKeycloakClient() (client gocloak.GoCloak, token *gocloak.JWT, e error) {

	keycloakService := d.getKeycloakService()
	client = gocloak.NewClient(keycloakService)
	ctx := context.Background()

	token, e = client.LoginClient(ctx, d.k.ClientID, d.k.ClientSecret, d.k.Realm)

	if e != nil {

		l.Warning.Printf("[DB] [KCSync] Error logging in to keycloak - %v\n", e.Error())

		return

	}

	return

}

// keycloakSync does a syncing between the users living in Keycloak to the db
// that the service uses as a source of truth.
func (d *DbParameter) KeycloakSync() {

	defer recoverKeycloakSync()

	var portalUsers []*models.User
	var keycloakUsers []*gocloak.User

	var portalUsersMap, onlyPortalUsersMap map[string]models.User
	var keycloakUsersMap, onlyKeycloakUsersMap map[string]gocloak.User

	c, t, e := d.getKeycloakClient()
	ctx := context.Background()

	if e != nil {

		l.Warning.Printf("[DB] [KCSync] Unable to adquire client from Keycloak, check with administrator.\n")

	} else {

		keycloakUsers, e = c.GetUsers(ctx, t.AccessToken, d.k.Realm, gocloak.GetUsersParams{})

		if e != nil {

			l.Warning.Printf("[DB] [KCSync] Unable to adquire users from Keycloak, check with administrator.\n")

		} else {

			l.Info.Printf("[DB] [KCSync] Success retrieving [ %v ] users from Keycloak", len(keycloakUsers))

			if e := d.Db.Find(&portalUsers).Error; e == nil {

				l.Info.Printf("[DB] [KCSync] Success retrieving [ %v ] users from PortalDB", len(portalUsers))

				l.Info.Printf("[DB] [KCSync] Users from Keycloak [ %v ], users from PortalDB [ %v ]", len(keycloakUsers), len(portalUsers))

				if len(keycloakUsers) < 1 {

					l.Warning.Printf("[DB] [KCSync] The amount of users coming from keycloak is too small, assuming failure in call and skipping silently...")

					return

				}

				if len(portalUsers) >= (len(keycloakUsers) + 10) {

					l.Warning.Printf("[DB] [KCSync] The amount of users coming from keycloak is too small compared to the amount of users from PortalDB (10+ users difference), assuming failure in call and skipping silently...")

					return

				}

				keycloakUsersMap = make(map[string]gocloak.User)
				onlyKeycloakUsersMap = make(map[string]gocloak.User)

				for i := range keycloakUsers {

					keycloakUsersMap[*keycloakUsers[i].ID] = *keycloakUsers[i]
					onlyKeycloakUsersMap[*keycloakUsers[i].ID] = *keycloakUsers[i]

				}

				portalUsersMap = make(map[string]models.User)
				onlyPortalUsersMap = make(map[string]models.User)

				for i := range portalUsers {

					portalUsersMap[portalUsers[i].ID.String()] = *portalUsers[i]
					onlyPortalUsersMap[portalUsers[i].ID.String()] = *portalUsers[i]

					delete(onlyKeycloakUsersMap, portalUsers[i].ID.String())

				}

				for id := range keycloakUsersMap {

					delete(onlyPortalUsersMap, id)

				}

				l.Warning.Printf("[DB] [KCSync] There's [ %v ] new user coming from Keycloak not present in PortalDB: [ %v ]", len(onlyKeycloakUsersMap), onlyKeycloakUsersMap)

				l.Warning.Printf("[DB] [KCSync] There's [ %v ] user in PortalDB not present in Keycloak: [ %v ]", len(onlyPortalUsersMap), onlyPortalUsersMap)

				for id := range onlyKeycloakUsersMap {

					user := onlyKeycloakUsersMap[id]

					l.Info.Printf("[DB] [KCSync] Adding new user [ %v ] from Keycloak to PortalDB", id)

					var newUser models.User

					newUser.ID = (strfmt.UUID)(id)

					if user.FirstName == nil || user.LastName == nil || user.Email == nil || user.Username == nil {

						l.Warning.Printf("[DB] [KCSync] User [ %v ] has some of the required fields missing, skipping silently...")

						continue

					}

					newUser.FirstName = *user.FirstName
					newUser.LastName = *user.LastName
					newUser.EmailAddress = (strfmt.Email)(*user.Email)
					newUser.Username = *user.Username
					newUser.RegistrationDateTime = (strfmt.DateTime)(time.Unix(*user.CreatedTimestamp/1000, 0).UTC())

					if e := d.Db.Create(&newUser).Error; e != nil {

						l.Warning.Printf("[DB] [KCSync] Problems adding keycloak user [ %v ] to the system, skipping silently...", id)

					} else {

						l.Info.Printf("[DB] [KCSync] Success syncing keycloak user [ %v ] on the system", id)

					}

				}

				for id := range onlyPortalUsersMap {

					user := onlyPortalUsersMap[id]

					l.Warning.Printf("[DB] [KCSync] Removing user [ %v ] from Portal since it is no longer in Keycloak", user.ID)

					if e := d.Db.Delete(&user).Error; e != nil {

						l.Warning.Printf("[DB] [KCSync] Problems removing user [ %v ] from the system, skipping silently...", id)

					} else {

						l.Info.Printf("[DB] [KCSync] Success removing user [ %v ] which was no longer present in Keycloak", id)

					}

				}

			} else {

				l.Warning.Printf("[DB] [KCSync] Problems retrieving users from PortalDB, skipping this sync-window silently... Error: %v", e)

			}

		}

	}

	return

}

// Function to skip the nil pointer exception that sometimes happens when someone
// tinkers with Keycloak users and misses some important field...
func recoverKeycloakSync() {

	if r := recover(); r != nil {

		l.Warning.Printf("[ALERT!!!] [DB] [KCSync] Seems like someone missed an important field when adding an user to keycloak... Error: %v\n", r)

	}

}

// IsShortNameAvailable job is toi check if the provided short name is already
// assigned to another project or if is still available.
// Parameters:
// - i: the input project short name to be checked in the system.
// Returns:
// - o: a bool to inform if the shortname is or not in use.
// - e: nil/error in case of a problem checking the shortname in the system.
func (d *DbParameter) IsShortNameAvailable(ctx context.Context, i string) (o bool, e error) {

	l.Trace.Printf("[DB] [PRJ] Checking if any Project has already assigned the shortname [ %v ].\n", i)

	r := d.Db.Where(&models.Project{ProjectShortName: i}).First(&models.Project{}).Error

	o = errors.Is(r, gorm.ErrRecordNotFound)

	if !o {

		l.Warning.Printf("[DB] [PRJ] The shortname [ %v ] is already in use or there's a problem in the query. Error: %v.\n", i, r)

		e = r

	}

	return

}

// AddUser function inserts the new user information into  the system.
// Parameters:
// - u: user's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem adding the item to the system.
func (d *DbParameter) AddUser(ctx context.Context, u models.User) (id strfmt.UUID, state int, e error) {

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	l.Trace.Printf("[DB] [USER] Attempting to add user [ %v ] by user [ %v ] now.\n", u.FirstName, authzData[SEC_USER])

	var u0 models.User

	orgs := strings.Split(authzData["ORG_WRITE"], ",")

	if len(orgs) < 1 {

		l.Warning.Printf("[DB] [USER] The user [ %v ] doesn't have an organization to which add a new user! \n", authzData[SEC_USER])

		e = fmt.Errorf("user doesn't have an organization to which add users - ORG_WRITE")

		state = statusFail

		return

	}

	if !d.isUserAllowed(u.OrganizationID.String(), "", "IAM_WRITE", authzData) {

		l.Warning.Printf("[DB] [USER] The user [ %v ] is not allowed to add users to organization [ %v ]! \n", authzData[SEC_USER], u.OrganizationID)

		e = fmt.Errorf("user doesn't have enough permissions for this organization - IAM_WRITE")

		state = statusForbidden

		return

	}

	if r := d.Db.Where(&u).First(&u0).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		_, token := kclib.GetToken()

		if token != "" {

			if u.OrganizationID != "" {

				_, perms := kclib.GetPermissionsFromRole("end_usr", u.OrganizationID.String(), "", "")
				status, _ := kclib.CreateUserWithOrg(token, u.Username, u.FirstName, u.LastName, u.EmailAddress.String(), u.OrganizationID.String(), perms)

				if status.IsSuccess() {

					l.Info.Printf("[DB] [USER] User [ %v ] added successfully to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", u.ID.String(), u.OrganizationID.String(), status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [USER] User [ %v ] couldn't be added to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", u.ID.String(), u.OrganizationID.String(), status.StatusCode, status.Message)

					e = fmt.Errorf("not able to add user to organization in Keycloak - KC-lib")

					state = statusFail

				}

			}

		} else {

			l.Warning.Printf("[DB] [USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

			e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

			state = statusFail

		}

		d.KeycloakSync()

		user := models.User{
			EmailAddress: u.EmailAddress,
			FirstName:    u.FirstName,
			LastName:     u.LastName,
		}

		if r := d.Db.Where(&user).First(&u0).Error; !errors.Is(r, gorm.ErrRecordNotFound) {

			if e := d.Db.Model(u0).Updates(u).Error; e == nil {

				l.Info.Printf("[DB] [USER] Fresly created user [ %v ] correctly synced from Keycloak into the system.\n", u.FirstName)

				state = statusOK

			} else {

				l.Warning.Printf("[DB] [USER] Unable to insert the record for user [ %v ] in the system, check with administrator.\n", u.FirstName)

				state = statusFail

			}

		} else {

			l.Warning.Printf("[DB] [USER] Unable to find the user [ %v ] in the system after a keycloak sync attemp, check with administrator.\n", u.FirstName)

			state = statusFail

		}

	} else {

		l.Warning.Printf("[DB] [USER] Record for user [ %v ] already exists, check with administrator.\n", u.FirstName)

		state = statusDuplicated

	}

	return

}

// DeleteUser function erases the user information linked to the provided id
// contained in the system.
// Parameters:
// - id: string with the id associated to the item that has to be deleted.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem deleting the item from the system.
func (d *DbParameter) DeleteUser(ctx context.Context, id strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [USER] Attempting to delete the user with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var u models.User

	state = statusOK

	tx := d.Db.Begin()

	if r := d.Db.Where(&models.User{ID: id}).First(&u).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [USER] Unable to fetch existing record for user [ %v ], check with administrator.\n", id)

		state = statusMissing

		return

	} else {

		l.Info.Printf("[DB] [USER] Found existing record for user [ %v ] successfully, proceeding to delete it.\n", u.FirstName)

		if !d.isUserAllowed(u.OrganizationID.String(), "", "IAM_WRITE", authzData) {

			l.Warning.Printf("[DB] [USER] The user [ %v ] is not allowed to remove users from organization [ %v ]! \n", authzData[SEC_USER], u.OrganizationID)

			e = fmt.Errorf("user doesn't have enough permissions in this organization - IAM_WRITE")

			state = statusForbidden

			return

		}

		if e := tx.Delete(&u).Error; e != nil {

			l.Warning.Printf("[DB] [USER] Unable to delete existing record for user [ %v ] from the system, check with administrator.\n", id)

			state = statusFail

		} else {

			l.Info.Printf("[DB] [USER] Existing record for user [ %v ] deleted successfully.\n", id)

			_, token := kclib.GetToken()

			if token != "" {

				status := kclib.DeleteUser(token, u.ID.String())

				if status.IsSuccess() {

					l.Info.Printf("[DB] [USER] User [ %v ] added successfully to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", u.ID.String(), u.OrganizationID.String(), status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [USER] User [ %v ] couldn't be added to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", u.ID.String(), u.OrganizationID.String(), status.StatusCode, status.Message)

					e = fmt.Errorf("not able to remove user from Keycloak - KC-lib")

					state = statusFail

				}

			} else {

				l.Warning.Printf("[DB] [USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

			}

		}

	}

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

// GetUser function retrieves the information contained in the system
// about the user whose id is provided.
// Parameters:
// - id: string with the id associated to the item that has to be retrieved.
// Returns:
// - reference to a user's model containing the information of the
// requested item.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) GetUser(ctx context.Context, id strfmt.UUID, permissions bool) (*models.User, int, error) {

	l.Trace.Printf("[DB] [USER] Attempting to fetch the user with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var u models.User
	var e error

	r := d.Db.Where(&models.User{ID: id}).First(&u)

	if !d.isUserAllowed(u.OrganizationID.String(), "", "IAM_READ", authzData) && !(id.String() == authzData[SEC_USER]) {

		return nil, statusForbidden, errors.New("not enough permissions to read user details - IAM_READ")

	}

	if errors.Is(r.Error, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [USER] Unable to fetch existing record for user [ %v ], check with administrator.\n", id)

		return nil, statusMissing, r.Error

	} else if e = r.Error; e != nil {

		l.Warning.Printf("[DB] [USER] Error in DB operation %v\n", e)

		return nil, statusFail, e

	}

	l.Info.Printf("[DB] [USER] Found existing record for user [ %v ] successfully.\n", u.FirstName)

	if permissions {

		u.Permissions, e = d.getPermissions(ctx, u.ID.String())

		if e != nil {

			l.Warning.Printf("[DB] [USER] Problems with Keycloak operation. Error: %v\n", e)

			return nil, statusForbidden, e

		}

	}

	return &u, statusOK, e

}

// ListUsers function retrieves all the users contained in the system.
// Returns:
// - Slice of user's model with all the users in the system.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) ListUsers(ctx context.Context, email strfmt.Email, project string, permissions bool, scope string) (u []*models.User, state int, e error) {

	l.Trace.Printf("[DB] [USER] Attempting to fetch users list now.\n")

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var uinit []*models.User
	var matcher string
	state = statusOK

	if len(strings.Split(authzData["IAM_LIST"], ",")) < 1 {

		//return nil, statusForbidden, errors.New("not enough permissions to list users in the system - IAM_LIST")
		var user *models.User

		user, state, e = d.GetUser(ctx, (strfmt.UUID)(authzData[SEC_USER]), permissions)

		if user != nil {

			u = append(u, user)

		}

		return

	}

	matchIN, matchANY := d.getMatchingList("organizationid", "allowedorganizations", "", strings.Split(authzData["IAM_LIST"], ","))

	if project != "" {

		matcher = fmt.Sprintf("'%v' = ANY(%v)", project, "projects")

	} else {

		switch scope {

		case "OWN":

			matcher = matchIN

		case "ALLOWED":

			matcher = matchANY

		case "ALL":

			if matchIN != "" && matchANY != "" {

				matcher = fmt.Sprintf("%v OR %v", matchIN, matchANY)

			} else if matchIN != "" {

				matcher = matchIN

			} else if matchANY != "" {

				matcher = matchANY

			}

		}

	}

	if email != "" {

		e = d.Db.Where(&models.User{EmailAddress: email}).Where(matcher).Find(&uinit).Error

	} else {

		e = d.Db.Where(matcher).Find(&uinit).Error

	}

	if e != nil {

		l.Warning.Printf("[DB] [USER] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	l.Trace.Printf("[DB] [USER] Found [ %d ] users in the db.\n", len(uinit))

	isInAlready := make(map[strfmt.UUID]struct{})

	for i, user := range uinit {

		if _, exists := isInAlready[user.ID]; exists {

			continue

		}

		if scope == "ALL" || scope == "OWN" {

			if d.isUserAllowed(uinit[i].OrganizationID.String(), "", "IAM_LIST", authzData) {

				////var user models.User

				////user.ID = uinit[i].ID
				////user.OrganizationID = uinit[i].OrganizationID
				////user.Projects = uinit[i].Projects
				////user.EmailAddress = uinit[i].EmailAddress
				user := *uinit[i]

				if permissions {

					var err error

					user.Permissions, err = d.getPermissions(ctx, user.ID.String())

					if err != nil {

						l.Warning.Printf("[DB] [USER] Problems with Keycloak operation. Error: %v\n", err)

						state = statusFail
						e = err

						return

					}

					isInAlready[user.ID] = struct{}{}

					u = append(u, &user)

				} else {

					isInAlready[user.ID] = struct{}{}

					u = append(u, &user)

				}

			}

			if scope == "OWN" {

				continue

			}

		}

		if scope == "ALL" || scope == "ALLOWED" {

			for _, org := range uinit[i].AllowedOrganizations {

				if _, exists := isInAlready[user.ID]; exists {

					continue

				}

				if d.isUserAllowed(org, "", "IAM_LIST", authzData) {

					////var user models.User

					////user.ID = uinit[i].ID
					////user.OrganizationID = uinit[i].OrganizationID
					////user.Projects = uinit[i].Projects
					////user.EmailAddress = uinit[i].EmailAddress
					user := *uinit[i]

					if permissions {

						var err error

						user.Permissions, err = d.getPermissions(ctx, user.ID.String())

						if err != nil {

							l.Warning.Printf("[DB] [USER] Problems with Keycloak operation. Error: %v\n", err)

							state = statusFail
							e = err

							return

						}

						isInAlready[user.ID] = struct{}{}

						u = append(u, &user)

					} else {

						isInAlready[user.ID] = struct{}{}

						u = append(u, &user)

					}

					break

				}

			}

		}

	}

	return

}

// UpdateUser function inserts the updated user information in the system.
// Parameters:
// - o: user's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - nil/error in case of a problem updating the item from the system.
func (d *DbParameter) UpdateUser(ctx context.Context, u models.User) (user *models.User, state int, e error) {

	l.Trace.Printf("[DB] [USER] Attempting to update user [ %v ] now.\n", u.FirstName)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var u0 models.User

	tx := d.Db.Begin()

	if r := d.Db.Where(&models.User{ID: u.ID}).First(&u0); !errors.Is(r.Error, gorm.ErrRecordNotFound) {

		if !d.isUserAllowed(u0.OrganizationID.String(), "", "IAM_WRITE", authzData) && !(u.ID.String() == authzData[SEC_USER]) {

			l.Warning.Printf("[DB] [USER] The user [ %v ] is not allowed to update users from organization [ %v ]! \n", authzData[SEC_USER], u.OrganizationID)

			e = fmt.Errorf("user doesn't have enough permissions in this organization - IAM_WRITE")

			state = statusForbidden

			return

		}

		u.OrganizationID = u0.OrganizationID

		if ret := tx.Model(&u0).Updates(u); ret.Error == nil {

			l.Info.Printf("[DB] [USER] Updated record for user [ %v ] on the system successfully.\n", u.FirstName)

			state = statusOK
			user = ret.Statement.Model.(*models.User)

			c, t, e := d.getKeycloakClient()

			if e != nil {

				l.Warning.Printf("[DB] [USER] Unable to adquire client from Keycloak, check with administrator. Error: %v\n", e)

				state = statusForbidden

			} else {

				user := gocloak.User{
					ID:        func(s string) *string { return &s }(u0.ID.String()),
					FirstName: &u0.FirstName,
					LastName:  &u0.LastName,
					Email:     func(s string) *string { return &s }(u0.EmailAddress.String()),
				}

				if u.FirstName != "" {

					user.FirstName = &u.FirstName

				}

				if u.LastName != "" {

					user.LastName = &u.LastName

				}

				if u.EmailAddress.String() != "" {

					user.Email = func(s string) *string { return &s }(u.EmailAddress.String())

				}

				e := c.UpdateUser(context.Background(), t.AccessToken, d.k.Realm, user)

				if e != nil {

					state = statusFail

					l.Warning.Printf("[DB] [USER] Unable to update record for user [ %v ] on Keycloak, check with administrator. Error: %v\n", u.ID, e)

				}

			}

		} else {

			l.Warning.Printf("[DB] [USER] Unable to update record for user [ %v ] on the system, check with administrator. Error: %v\n", u.FirstName, e)

			state = statusFail

		}

	} else {

		l.Warning.Printf("[DB] [USER] Record for user [ %v ] not found, check with administrator.\n", u.FirstName)

		state = statusMissing

	}

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

// AddOrganization function inserts the new organization information into  the system.
// Parameters:
// - o: organization's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem adding the item to the system.
func (d *DbParameter) AddOrganization(ctx context.Context, o models.Organization) (id strfmt.UUID, state int, e error) {

	l.Trace.Printf("[DB] [ORG] Attempting to add Organization [ %v ] by user [ %v ].\n", o.FormalName, o.CreatedBy)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var o0 models.Organization
	var user models.User

	if e = d.Db.Where(&models.User{ID: (strfmt.UUID)(authzData[SEC_USER])}).First(&user).Error; e != nil {

		l.Warning.Printf("[DB] [ORG] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	// Ensuring the creator is the one making the call
	o.CreatedBy = (strfmt.UUID)(authzData[SEC_USER])
	o.CreationDate = (strfmt.DateTime)(time.Now())

	if user.OrganizationID.String() != "" {

		l.Warning.Printf("[DB] [ORG] The user [ %v ] already has the organization [ %v ] linked! \n", user.ID, user.OrganizationID)

		e = fmt.Errorf("user already has an organization - DB-Check")

		state = statusForbidden

		return

	}

	tx := d.Db.Begin()

	if r := tx.Where(&o).First(&o0).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		if r := tx.Create(&o); r.Error == nil {

			l.Info.Printf("[DB] [ORG] Inserted new record for organization [ %v ] successfully.\n", o.FormalName)

			state = statusOK
			id = r.Statement.Model.(*models.Organization).ID

			_, token := kclib.GetToken()

			if token != "" {

				status := kclib.CreateOrganization(token, id.String())

				if status.IsSuccess() {

					l.Info.Printf("[DB] [ORG] Organization [ %v ] created successfully in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [ORG] Organization [ %v ] failed to be created in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to create organization in Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [ORG] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

				goto checkForFailure

			}

			if u, _, e := d.GetUser(ctx, o.CreatedBy, false); e == nil {

				if e := tx.Model(u).Updates(models.User{OrganizationID: id}).Error; e == nil {

					l.Info.Printf("[DB] [ORG] The status of user [ %v ] creating the organization [ %v ] has been upgraded successfully.\n", o.CreatedBy, o.FormalName)

					state = statusOK

					if token != "" {

						_, perms := kclib.GetPermissionsFromRole("org_mgr", id.String(), "", "")
						status := kclib.AddUserToOrg(token, o.CreatedBy.String(), id.String(), perms)

						if status.IsSuccess() {

							l.Info.Printf("[DB] [ORG] User [ %v ] added successfully to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", u.ID, id, status.StatusCode, status.Message)

						} else {

							l.Warning.Printf("[DB] [ORG] User [ %v ] couldn't be added to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

							e = fmt.Errorf("not able to create the user in Keycloak - KC-lib")

							state = statusFail

							goto checkForFailure

						}

					} else {

						l.Warning.Printf("[DB] [ORG] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

						e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

						state = statusFail

						goto checkForFailure

					}

				} else {

					l.Warning.Printf("[DB] [ORG] Error when updating the user [ %v ] supposed to be the creator of the organization doesn't exist, check with administrator. Error: %v\n", o.CreatedBy, e)

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [ORG] Error when retrieving the user [ %v ] supposed to be the creator of the organization doesn't exist, check with administrator. Error: %v\n", o.CreatedBy, e)

				state = statusFail

				goto checkForFailure

			}

		} else {

			l.Warning.Printf("[DB] [ORG] Unable to insert the record for organization [ %v ], check with administrator.\n", o.FormalName)

			state = statusFail

			goto checkForFailure

		}

	} else {

		l.Warning.Printf("[DB] [ORG] Record for organization [ %v ] already exists, check with administrator.\n", o.FormalName)

		state = statusDuplicated

	}

checkForFailure:

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

// DeleteOrganization function erases the organization information linked to the
// provided id contained in the system.
// Parameters:
// - id: string with the id associated to the item that has to be deleted.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem deleting the item from the system.
func (d *DbParameter) DeleteOrganization(ctx context.Context, id strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [ORG] Attempting to delete the organization with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var o models.Organization

	state = statusOK

	tx := d.Db.Begin()

	if r := d.Db.Where(&models.Organization{ID: id}).First(&o).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [ORG] Unable to fetch existing record for organization [ %v ], check with administrator.\n", id)

		state = statusMissing

		return

	} else {

		l.Info.Printf("[DB] [ORG] Found existing record for organization [ %v ] successfully, proceeding to delete it.\n", o.FormalName)

		if !d.isUserAllowed(id.String(), "", "ORG_WRITE", authzData) {

			l.Warning.Printf("[DB] [ORG] The user [ %v ] is not allowed to remove the organization [ %v ]! \n", authzData[SEC_USER], id)

			e = fmt.Errorf("user doesn't have enough permissions in this organization - ORG_WRITE")

			state = statusForbidden

			return

		}

		if e = tx.Delete(&o).Error; e != nil {

			state = statusFail

			l.Warning.Printf("[DB] [ORG] Unable to delete existing record for organization [ %v ], check with administrator.\n", id)

		} else {

			l.Info.Printf("[DB] [ORG] Existing record for organization [ %v ] deleted successfully.\n", id)

			_, token := kclib.GetToken()

			if token != "" {

				status := kclib.DeleteOrganization(token, id.String())

				if status.IsSuccess() {

					l.Info.Printf("[DB] [ORG] Organization [ %v ] deleted successfully in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [ORG] Failed to delete Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to delete organization from Keycloak - KC-lib")

					state = statusFail

				}

			} else {

				l.Warning.Printf("[DB] [ORG] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

			}

		}

	}

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

// GetOrganization function retrieves the information contained in the system
// about the organization whose id is provided.
// Parameters:
// - id: string with the id associated to the item that has to be retrieved.
// Returns:
// - reference to a organization's model containing the information of the
// requested item.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) GetOrganization(ctx context.Context, id strfmt.UUID) (*models.Organization, int, error) {

	l.Trace.Printf("[DB] [ORG] Attempting to fetch the organization with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var o models.Organization
	var e error

	r := d.Db.Where(&models.Organization{ID: id}).First(&o)

	if !d.isUserAllowed(id.String(), "", "ORG_READ", authzData) {

		return nil, statusForbidden, errors.New("not enough permissions to read organization details - ORG_READ")

	}

	if errors.Is(r.Error, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [ORG] Unable to fetch existing record for organization [ %v ], check with administrator.\n", id)

		return nil, statusMissing, r.Error

	} else if e = r.Error; e != nil {

		l.Warning.Printf("[DB] [ORG] Error in DB operation %v\n", e)

		return nil, statusFail, e

	}

	l.Info.Printf("[DB] [ORG] Found existing record for organization [ %v ] successfully.\n", o.FormalName)

	return &o, statusOK, e

}

// ListOrganizations function retrieves all the organizations contained in the
// system.
// Returns:
// - Slice of organization's model with all the organizations in the system.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) ListOrganizations(ctx context.Context, scope string) (o []*models.Organization, state int, e error) {

	l.Trace.Printf("[DB] [ORG] Attempting to fetch organization list now.\n")

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	if len(strings.Split(authzData["ORG_LIST"], ",")) < 1 {

		return nil, statusForbidden, errors.New("not enough permissions to list organizations in the system - ORG_LIST")

	}

	var oinit []*models.Organization
	var matcher string
	var user models.User

	if e = d.Db.Where(&models.User{ID: (strfmt.UUID)(authzData[SEC_USER])}).First(&user).Error; e != nil {

		l.Warning.Printf("[DB] [ORG] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	matchOWN, _ := d.getMatchingList("id", "", user.OrganizationID.String(), nil)
	matchALLOWED, _ := d.getMatchingList("id", "", "", user.AllowedOrganizations)

	switch scope {

	case "OWN":

		matcher = matchOWN

	case "ALLOWED":

		matcher = matchALLOWED

	case "ALL":

		if matchOWN != "" && matchALLOWED != "" {

			matcher = fmt.Sprintf("%v OR %v", matchOWN, matchALLOWED)

		} else if matchOWN != "" {

			matcher = matchOWN

		} else if matchALLOWED != "" {

			matcher = matchALLOWED

		}

	}

	if e = d.Db.Where(matcher).Find(&oinit).Error; e != nil {

		l.Warning.Printf("[DB] [ORG] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	l.Trace.Printf("[DB] [ORG] Found [ %d ] organizations in the db.\n", len(oinit))

	for i := range oinit {

		if scope == "OWN" {

			if oinit[i].ID.String() == user.OrganizationID.String() {

				if d.isUserAllowed(oinit[i].ID.String(), "", "ORG_LIST", authzData) {

					////var org models.Organization

					////org.ID = oinit[i].ID
					////org.FormalName = oinit[i].FormalName

					org := *oinit[i]

					o = append(o, &org)

				}

			}

			continue

		}

		if d.isUserAllowed(oinit[i].ID.String(), "", "ORG_LIST", authzData) {

			////var org models.Organization

			////org.ID = oinit[i].ID
			////org.FormalName = oinit[i].FormalName

			org := *oinit[i]

			o = append(o, &org)

		}

	}

	return

}

// UpdateOrganization function inserts the updated organization information in
// the system.
// Parameters:
// - o: organization's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - nil/error in case of a problem updating the item from the system.
func (d *DbParameter) UpdateOrganization(ctx context.Context, o models.Organization) (org *models.Organization, state int, e error) {

	l.Trace.Printf("[DB] [ORG] Attempting to update organization [ %v ] now.\n", o.FormalName)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var o0 models.Organization

	if r := d.Db.Where(&models.Organization{ID: o.ID}).First(&o0); !errors.Is(r.Error, gorm.ErrRecordNotFound) {

		if !d.isUserAllowed(o.ID.String(), "", "ORG_WRITE", authzData) {

			l.Warning.Printf("[DB] [ORG] The user [ %v ] is not allowed to edit this organization [ %v ]! \n", authzData[SEC_USER], o.ID)

			e = fmt.Errorf("user doesn't have enough permissions in this organization - ORG_WRITE")

			state = statusForbidden

			return

		}

		// Ensure that the creator remanins untouch
		o.CreatedBy = o0.CreatedBy

		ret := d.Db.Model(&o0).Updates(o)

		if ret.Error == nil {

			l.Info.Printf("[DB] [ORG] Updated record for organization [ %v ] successfully.\n", o.FormalName)

			org = ret.Statement.Model.(*models.Organization)

			state = statusOK

			return

		}

		l.Warning.Printf("[DB] [ORG] Unable to update record for organization [ %v ], check with administrator.\n", o.FormalName)

		state = statusFail

		e = ret.Error

		return

	}

	l.Warning.Printf("[DB] [ORG] Record for organization [ %v ] not found, check with administrator.\n", o.FormalName)

	state = statusMissing

	return

}

// AddProject function inserts the new project information into  the system.
// Parameters:
// - p: project's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem adding the item to the system.
func (d *DbParameter) AddProject(ctx context.Context, p models.Project) (id strfmt.UUID, state int, e error) {

	l.Trace.Printf("[DB] [PRJ] Attempting to add Project [ %v ] for Organization [ %v ] now.\n", p.ProjectName, p.LinkedOrganization)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	p.ProjectCreationTime = (strfmt.DateTime)(time.Now())

	if !d.validDates(p.ProjectStartDate, p.ProjectTerminationDate) {

		l.Warning.Printf("[DB] [PRJ] The dates of the project are not valid: either in the past or the end is before the start!\n")

		e = fmt.Errorf("project dates are invalid! Do not try to use dates in the past or not logical")

		state = statusFail

		return

	}

	var p0 models.Project
	var user models.User

	if e = d.Db.Where(&models.User{ID: (strfmt.UUID)(authzData[SEC_USER])}).First(&user).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	// Ensuring the creator is the one making the call
	p.ProjectCreatedBy = (strfmt.UUID)(authzData[SEC_USER])

	if !d.isUserAllowed(p.LinkedOrganization.String(), "", "ORG_WRITE", authzData) {

		l.Warning.Printf("[DB] [PRJ] The user [ %v ] doesn't have enough permissions in the linked organization [ %v ]!\n", user.ID, user.OrganizationID)

		e = fmt.Errorf("user without enough permission in organization - ORG_WRITE")

		state = statusForbidden

		return

	}

	tx := d.Db.Begin()

	if r := tx.Where(&p).First(&p0).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		if r := tx.Create(&p); r.Error == nil {

			l.Info.Printf("[DB] [PRJ] Inserted new record for project [ %v ] successfully.\n", p.ProjectName)

			state = statusOK
			id = r.Statement.Model.(*models.Project).ProjectID

			u := user
			u.Projects = append(user.Projects, id.String())

			if e := tx.Model(user).Updates(u).Error; e == nil {

				l.Info.Printf("[DB] [PRJ-USER] User [ %v ] correctly added to Project [ %v ] in the system.\n", user.FirstName, id)

			} else {

				state = statusFail

				goto checkForFailure

			}

			_, token := kclib.GetToken()

			if token != "" {

				status := kclib.CreateProject(token, p.ProjectShortName, id.String(), []string{p.LinkedOrganization.String()})

				if status.IsSuccess() {

					l.Info.Printf("[DB] [PRJ] Project [ %v ] created successfully in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

					_, perms := kclib.GetPermissionsFromRole("org_mgr", p.LinkedOrganization.String(), p.ProjectShortName, id.String())
					statusAdd := kclib.AddUserToProject(token, p.ProjectCreatedBy.String(), id.String(), p.LinkedOrganization.String(), perms)

					if statusAdd.IsSuccess() {

						l.Info.Printf("[DB] [PRJ] User [ %v ] added as [ %v ] to Project [ %v ] successfully in Keycloak: [ %v ] - [ %v ]\n", p.ProjectCreatedBy.String(), "org_mgr", id, statusAdd.StatusCode, statusAdd.Message)

					} else {

						l.Warning.Printf("[DB] [PRJ] User [ %v ] couldn't be added as [ %v ] to Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", p.ProjectCreatedBy.String(), "org_mgr", id, statusAdd.StatusCode, statusAdd.Message)

						e = fmt.Errorf("not able to add user to project in Keycloak - KC-lib")

						state = statusFail

						goto checkForFailure

					}

					_, perms = kclib.GetPermissionsFromRole("prj_mgr", p.LinkedOrganization.String(), p.ProjectShortName, id.String())
					statusAdd = kclib.AddUserToProject(token, p.ProjectCreatedBy.String(), id.String(), p.LinkedOrganization.String(), perms)

					if statusAdd.IsSuccess() {

						l.Info.Printf("[DB] [PRJ] User [ %v ] added as [ %v ] to Project [ %v ] successfully in Keycloak: [ %v ] - [ %v ]\n", p.ProjectCreatedBy.String(), "prj_mgr", id, statusAdd.StatusCode, statusAdd.Message)

					} else {

						l.Warning.Printf("[DB] [PRJ] User [ %v ] couldn't be added as [ %v ] to Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", p.ProjectCreatedBy.String(), "prj_mgr", id, statusAdd.StatusCode, statusAdd.Message)

						e = fmt.Errorf("not able to add user to project in Keycloak - KC-lib")

						state = statusFail

						goto checkForFailure

					}

				} else {

					l.Warning.Printf("[DB] [PRJ] Project [ %v ] failed to be created in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to create project in Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [PRJ] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

				goto checkForFailure

			}

		} else {

			l.Warning.Printf("[DB] [PRJ] Unable to insert the record for organization [ %v ], check with administrator.\n", p.ProjectName)

			state = statusFail

			goto checkForFailure

		}

	} else {

		l.Warning.Printf("[DB] [PRJ] Record for project [ %v ] already exists, check with administrator.\n", p.ProjectName)

		state = statusDuplicated

	}

checkForFailure:

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

// DeleteProject function erases the project information linked to the
// provided id contained in the system.
// Parameters:
// - id: string with the id associated to the item that has to be deleted.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem deleting the item from the system.
func (d *DbParameter) DeleteProject(ctx context.Context, id strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [PRJ] Attempting to delete the project with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var p models.Project

	state = statusOK

	tx := d.Db.Begin()

	if r := d.Db.Where(&models.Project{ProjectID: id}).First(&p).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [PRJ] Unable to fetch existing record for project [ %v ], check with administrator.\n", id)

		state = statusMissing

		return

	} else {

		l.Info.Printf("[DB] [PRJ] Found existing record for project [ %v ] successfully, proceeding to delete it.\n", p.ProjectName)

		if !d.isUserAllowed(p.LinkedOrganization.String(), id.String(), "PRJ_WRITE", authzData) {

			l.Warning.Printf("[DB] [PRJ] The user [ %v ] is not allowed to remove the project [ %v ]! \n", authzData[SEC_USER], id)

			e = fmt.Errorf("user doesn't have enough permissions in this organization PRJ_WRITE")

			state = statusForbidden

			return

		}

		if e = tx.Delete(&p).Error; e != nil {

			state = statusFail

			l.Warning.Printf("[DB] [PRJ] Unable to delete existing record for project [ %v ], check with administrator.\n", id)

		} else {

			l.Info.Printf("[DB] [PRJ] Existing record for project [ %v ] deleted successfully.\n", id)

			_, token := kclib.GetToken()

			if token != "" {

				status := kclib.DeleteProject(token, id.String())

				if status.IsSuccess() {

					l.Info.Printf("[DB] [PRJ] Project [ %v ] deleted successfully in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [PRJ] Failed to delete Project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", id, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to delete project in Keycloak - KC-lib")

					state = statusFail

				}

			} else {

				l.Warning.Printf("[DB] [PRJ] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

			}

		}

	}

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

// GetProject function retrieves the information contained in the system
// about the project whose id is provided.
// Parameters:
// - id: string with the id associated to the item that has to be retrieved.
// Returns:
// - reference to a project's model containing the information of the
// requested item.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) GetProject(ctx context.Context, id strfmt.UUID) (*models.Project, int, error) {

	l.Trace.Printf("[DB] [PRJ] Attempting to fetch the project with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var p models.Project
	var e error

	r := d.Db.Where(&models.Project{ProjectID: id}).First(&p)

	if !d.isUserAllowed(p.LinkedOrganization.String(), id.String(), "PRJ_READ", authzData) {

		return nil, statusForbidden, errors.New("not enough permissions to read project details - PRJ_READ")

	}

	if errors.Is(r.Error, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [PRJ] Unable to fetch existing record for project [ %v ], check with administrator.\n", id)

		return nil, statusMissing, r.Error

	} else if e = r.Error; e != nil {

		l.Warning.Printf("[DB] [PRJ] Error in DB operation %v\n", e)

		return nil, statusFail, e

	}

	l.Info.Printf("[DB] [PRJ] Found existing record for project [ %v ] successfully.\n", p.ProjectName)

	return &p, statusOK, e

}

// ListProjects function retrieves all the projects contained in the system.
// Returns:
// - Slice of project's model with all the projects in the system.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) ListProjects(ctx context.Context, scope string) (p []*models.Project, state int, e error) {

	l.Trace.Printf("Attempting to fetch project list now.\n")

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	if len(strings.Split(authzData["PRJ_LIST"], ",")) < 1 {

		// Workaround to not give a 403 in the edge cases of an user without projects
		//return nil, statusForbidden, errors.New("not enough permissions to list projects in the system - PRJ_LIST")

		state = statusOK

		return

	}

	var pinit []*models.Project
	var matcher string
	var user models.User

	if e = d.Db.Where(&models.User{ID: (strfmt.UUID)(authzData[SEC_USER])}).First(&user).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	matchIN, matchANY := d.getMatchingList("linkedorganization", "allowedorganizations", user.OrganizationID.String(), strings.Split(authzData["ORG_LIST"], ","))

	switch scope {

	case "OWN":

		matcher = matchIN

	case "ALLOWED":

		matcher = matchANY

	case "ALL":

		if matchIN != "" && matchANY != "" {

			matcher = fmt.Sprintf("%v OR %v", matchIN, matchANY)

		} else if matchIN != "" {

			matcher = matchIN

		} else if matchANY != "" {

			matcher = matchANY

		}

	}

	if e = d.Db.Where(matcher).Find(&pinit).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	l.Trace.Printf("[DB] [PRJ] Found [ %d ] project in the db.\n", len(pinit))

	for i := range pinit {

		if scope == "OWN" {

			if d.isUserAllowed(user.OrganizationID.String(), pinit[i].ProjectID.String(), "PRJ_LIST", authzData) {

				////var prj models.Project

				////prj.ProjectID = pinit[i].ProjectID
				////prj.LinkedOrganization = pinit[i].LinkedOrganization

				prj := *pinit[i]

				p = append(p, &prj)

			}

			continue

		}

		if d.isUserAllowed("", pinit[i].ProjectID.String(), "PRJ_LIST", authzData) {

			////var prj models.Project

			////prj.ProjectID = pinit[i].ProjectID
			////prj.LinkedOrganization = pinit[i].LinkedOrganization

			prj := *pinit[i]

			p = append(p, &prj)

		}

	}

	return

}

// UpdateProject function inserts the updated project information in
// the system.
// Parameters:
// - p: project's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - nil/error in case of a problem updating the item from the system.
func (d *DbParameter) UpdateProject(ctx context.Context, p models.Project) (prj *models.Project, state int, e error) {

	l.Trace.Printf("[DB] [PRJ] Attempting to update project [ %v ] now.\n", p.ProjectName)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var p0 models.Project

	if r := d.Db.Where(&models.Project{ProjectID: p.ProjectID}).First(&p0); !errors.Is(r.Error, gorm.ErrRecordNotFound) {

		if !d.isUserAllowed("", p.ProjectID.String(), "PRJ_WRITE", authzData) {

			l.Warning.Printf("[DB] [PRJ] The user [ %v ] is not allowed to edit this project [ %v ]! \n", authzData[SEC_USER], p.ProjectID)

			e = fmt.Errorf("user doesn't have enough permissions in this project - PRJ_WRITE")

			state = statusForbidden

			return

		}

		// Ensuring the creator is the one making the call
		p.ProjectCreatedBy = (strfmt.UUID)(authzData[SEC_USER])

		// Ensure there's no changes in Organizaions linked/allowed
		p.LinkedOrganization = p0.LinkedOrganization
		p.AllowedOrganizations = p0.AllowedOrganizations

		ret := d.Db.Model(&p0).Updates(p)

		if ret.Error == nil {

			l.Info.Printf("[DB] [PRJ] Updated record for project [ %v ] successfully.\n", p.ProjectName)

			prj = ret.Statement.Model.(*models.Project)

			state = statusOK

			return

		}

		l.Warning.Printf("[DB] [PRJ] Unable to update record for project [ %v ], check with administrator.\n", p.ProjectName)

		state = statusFail

		return

	}

	l.Warning.Printf("[DB] [PRJ] Record for project [ %v ] not found, check with administrator.\n", p.ProjectName)

	state = statusMissing

	return

}

// AddHPCResource function inserts the new HPCResource information into the system.
// Parameters:
// - o: HPCResource's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem adding the item to the system.
func (d *DbParameter) AddHPCResource(ctx context.Context, h models.HPCResource) (id string, state int, e error) {

	l.Trace.Printf("[DB] [HPCRes] Attempting to add HPCResource [ %v ] now.\n", h.AssociatedHPCProject)

	var h0 models.HPCResource

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var user models.User

	if e = d.Db.Where(&models.User{ID: (strfmt.UUID)(authzData[SEC_USER])}).First(&user).Error; e != nil {

		l.Warning.Printf("[DB] [HPHRes] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	if !d.isUserAllowed("", h.AssociatedLEXISProject.String(), "PRJ_WRITE", authzData) {

		l.Warning.Printf("[DB] [PRJ] The user [ %v ] doesn't have enough permissions in the linked project [ %v ]!\n", user.ID, user.OrganizationID)

		e = fmt.Errorf("user without enough permission in theproject - PRJ_WRITE")

		state = statusForbidden

		return

	}

	if r := d.Db.Where(&h).First(&h0).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		if r := d.Db.Create(&h); r.Error == nil {

			state = statusOK
			id = r.Statement.Model.(*models.HPCResource).HPCResourceID

			l.Info.Printf("[DB] [HPCRes] Inserted new record for HPCResource [ %v ] successfully.\n", id)

		} else {

			l.Warning.Printf("[DB] [HPCRes] Unable to insert the record for HPCResource [ %v ], check with administrator.\n", h.AssociatedHPCProject)

			state = statusFail

		}

	} else {

		l.Warning.Printf("[DB] [HPCRes] Record for HPCResource [ %v ] already exists, check with administrator.\n", h.AssociatedHPCProject)

		state = statusDuplicated

	}

	return

}

// DeleteHPCResource function erases the HPCResource information linked to the
// provided id contained in the system.
// Parameters:
// - id: string with the id associated to the item that has to be deleted.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - e: nil/error in case of a problem deleting the item from the system.
func (d *DbParameter) DeleteHPCResource(ctx context.Context, id string) (state int, e error) {

	l.Trace.Printf("[DB] [HPCRes] Attempting to delete the organization with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var h models.HPCResource

	state = statusOK

	if r := d.Db.Where(&models.HPCResource{HPCResourceID: id}).First(&h).Error; errors.Is(r, gorm.ErrRecordNotFound) {

		state = statusMissing

		l.Warning.Printf("[DB] [HPCRes] Unable to fetch existing record for HPCResource [ %v ], check with administrator.\n", id)

	} else {

		l.Info.Printf("[DB] [HPCRes] Found existing record for HPCResource [ %v ] successfully, proceeding to delete it.\n", h.HPCResourceID)

		if !d.isUserAllowed("", h.AssociatedLEXISProject.String(), "PRJ_WRITE", authzData) {

			l.Warning.Printf("[DB] [HPCRes] The user [ %v ] is not allowed to remove the HPCResource [ %v ]! \n", authzData[SEC_USER], id)

			e = fmt.Errorf("user doesn't have enough permissions in this project - PRJ_WRITE")

			state = statusForbidden

			return

		}

		if e = d.Db.Delete(&h).Error; e != nil {

			state = statusFail

			l.Warning.Printf("[DB] [HPCRes] Unable to delete existing record for HPCResource [ %v ], check with administrator.\n", id)

		} else {

			l.Info.Printf("[DB] [HPCRes] Existing record for HPCResource [ %v ] deleted successfully.\n", id)

		}

	}

	return

}

// GetHPCResource function retrieves the information contained in the system
// about the HPCResource whose id is provided.
// Parameters:
// - id: string with the id associated to the item that has to be retrieved.
// Returns:
// - reference to a HPCResource's model containing the information of the
// requested item.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) GetHPCResource(ctx context.Context, id string) (*models.HPCResource, int, error) {

	l.Trace.Printf("[DB] [HPCRes] Attempting to fetch the HPCResource with id %v.\n", id)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var h models.HPCResource
	var e error

	r := d.Db.Where(&models.HPCResource{HPCResourceID: id}).First(&h)

	if !d.isUserAllowed("", h.AssociatedLEXISProject.String(), "PRJ_READ", authzData) {

		return nil, statusForbidden, errors.New("not enough permissions to read project details - PRJ_READ")

	}

	if errors.Is(r.Error, gorm.ErrRecordNotFound) {

		l.Warning.Printf("[DB] [HPCRes] Unable to fetch existing record for HPCResource [ %v ], check with administrator.\n", id)

		return nil, statusMissing, r.Error

	} else if e = r.Error; e != nil {

		l.Warning.Printf("[DB] [HPCRes] Error in DB operation %v\n", e)

		return nil, statusFail, e

	}

	l.Info.Printf("[DB] [HPCRes] Found existing record for HPCResource [ %v ] successfully.\n", h.HPCResourceID)

	return &h, statusOK, e

}

// ListHPCResources function retrieves all the HPCResources contained in the
// system.
// Returns:
// - Slice of HPCResource's model with all the HPCResources in the system.
// - nil/error in case of a problem retrieving the item from the system.
func (d *DbParameter) ListHPCResources(ctx context.Context, scope string) (h []*models.HPCResource, state int, e error) {

	l.Trace.Printf("Attempting to fetch HPCResource list now.\n")

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	if len(strings.Split(authzData["PRJ_LIST"], ",")) < 1 {

		return nil, statusForbidden, errors.New("not enough permissions to list HPC Resources in the system - PRJ_LIST")

	}

	var hinit []*models.HPCResource
	var matcher string
	var user models.User

	if e = d.Db.Where(&models.User{ID: (strfmt.UUID)(authzData[SEC_USER])}).First(&user).Error; e != nil {

		l.Warning.Printf("[DB] [HPCRes] Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	var projects []string

	for _, pair := range strings.Split(authzData["PRJ_LIST"], ",") {

		v := strings.Split(pair, "/")

		if len(v) > 1 {

			projects = append(projects, v[1])

		}

	}

	matcher, _ = d.getMatchingList("associatedlexisproject", "", "", projects)

	if e = d.Db.Where(matcher).Find(&hinit).Error; e != nil {

		l.Warning.Printf("Error in DB operation %v\n", e)

		state = statusFail

		return

	}

	l.Trace.Printf("Found [ %d ] HPCResources in the db.\n", len(hinit))

	for i := range hinit {

		if scope == "OWN" {

			if d.isUserAllowed(user.OrganizationID.String(), hinit[i].AssociatedLEXISProject.String(), "PRJ_LIST", authzData) {

				////var hpc models.HPCResource

				////hpc.HPCResourceID = hinit[i].HPCResourceID
				////hpc.AssociatedLEXISProject = hinit[i].AssociatedLEXISProject
				////hpc.AssociatedHPCProject = hinit[i].AssociatedHPCProject

				hpc := *hinit[i]

				h = append(h, &hpc)

			}

			continue

		}

		if d.isUserAllowed("", hinit[i].AssociatedLEXISProject.String(), "PRJ_LIST", authzData) {

			////var hpc models.HPCResource

			////hpc.HPCResourceID = hinit[i].HPCResourceID
			////hpc.AssociatedLEXISProject = hinit[i].AssociatedLEXISProject
			////hpc.AssociatedHPCProject = hinit[i].AssociatedHPCProject

			hpc := *hinit[i]

			h = append(h, &hpc)

		}

	}

	return

}

// UpdateHPCResource function inserts the updated HPCResource information in
// the system.
// Parameters:
// - o: HPCResource's model containing the information to be imported in the db.
// Returns:
// - state: int representing the state of the operation for a proper anwser
// and error handling in the endpoint.
// - nil/error in case of a problem updating the item from the system.
func (d *DbParameter) UpdateHPCResource(ctx context.Context, h models.HPCResource) (hpr *models.HPCResource, state int, e error) {

	l.Trace.Printf("Attempting to update HPCResource [ %v ] now.\n", h.HPCResourceID)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	var h0 models.HPCResource

	if r := d.Db.Where(&models.HPCResource{HPCResourceID: h.HPCResourceID}).First(&h0); !errors.Is(r.Error, gorm.ErrRecordNotFound) {

		if !d.isUserAllowed("", h0.AssociatedLEXISProject.String(), "PRJ_WRITE", authzData) {

			l.Warning.Printf("[DB] [PRJ] The user [ %v ] is not allowed to edit this project [ %v ]! \n", authzData[SEC_USER], h.AssociatedLEXISProject)

			e = fmt.Errorf("user doesn't have enough permissions in this project - PRJ_WRITE")

			state = statusForbidden

			return

		}

		// Ensuring the AssociatedLEXISProject is not changed here
		h.AssociatedLEXISProject = h0.AssociatedLEXISProject

		if ret := d.Db.Model(&h0).Updates(h); ret.Error == nil {

			l.Info.Printf("Updated record for HPCResource [ %v ] successfully.\n", h.HPCResourceID)

			hpr = ret.Statement.Model.(*models.HPCResource)

			state = statusOK

			return

		}

		l.Warning.Printf("Unable to update record for HPCResource [ %v ], check with administrator.\n", h.HPCResourceID)

		state = statusFail

		return

	}

	l.Warning.Printf("Record for HPCResource [ %v ] not found, check with administrator.\n", h.HPCResourceID)

	state = statusMissing

	return

}

func (d *DbParameter) AddUserToOrg(ctx context.Context, user, destination strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [ORG-USER] Attempting to add user [ %v ] to organization [ %v ] now.\n", user, destination)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	var u0, u models.User
	var org models.Organization

	if e = d.Db.Where(models.Organization{ID: destination}).First(&org).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ-USER] Something went wrong when trying to retrieve the organization [ %v ]\n", destination)

		state = statusMissing

		return

	}

	if !d.isUserAllowed(destination.String(), "", "IAM_WRITE", authzData) {

		l.Warning.Printf("[DB] [ORG-USER] The user [ %v ] is not allowed to add anyone to this organization [ %v ]! \n", authzData[SEC_USER], destination)

		e = fmt.Errorf("user doesn't have enough permissions in this organization - IAM_WRITE")

		state = statusForbidden

		return

	}

	tx := d.Db.Begin()

	if r := d.Db.Where(models.User{ID: user}).First(&u0).Error; !errors.Is(r, gorm.ErrRecordNotFound) {

		u.AllowedOrganizations = append(u0.AllowedOrganizations, destination.String())

		if e := tx.Model(u0).Updates(u).Error; e == nil {

			l.Info.Printf("[DB] [ORG-USER] User [ %v ] correctly added to Organization [ %v ] in the system.\n", u0.FirstName, destination)

			_, token := kclib.GetToken()

			if token != "" {

				_, perms := kclib.GetPermissionsFromRole("end_usr", destination.String(), "", "")
				status := kclib.AddUserToOrg(token, user.String(), destination.String(), perms)

				if status.IsSuccess() {

					l.Info.Printf("[DB] [ORG-USER] User [ %v ] added successfully to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [ORG-USER] User [ %v ] couldn't be added to Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to add user to organization in Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [ORG-USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

				goto checkForFailure

			}

		} else {

			l.Warning.Printf("[DB] [ORG-USER] Unable to add user [ %v ] to organization [ %v ] in the system, check with administrator.\n", u0.FirstName, destination)

			state = statusFail

			goto checkForFailure

		}

	} else {

		l.Warning.Printf("[DB] [ORG-USER] Unable to find the user [ %v ] in the system.\n", user)

		state = statusMissing

		return

	}

checkForFailure:

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

func (d *DbParameter) AddUserToPrj(ctx context.Context, user, destination strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [PRJ-USER] Attempting to add user [ %v ] to project [ %v ] now.\n", user, destination)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	var u0, u models.User
	var prj models.Project

	if e = d.Db.Where(models.Project{ProjectID: destination}).First(&prj).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ-USER] Something went wrong when trying to retrieve the project [ %v ]\n", destination)

		state = statusMissing

		return

	}

	if !d.isUserAllowed(prj.LinkedOrganization.String(), "", "IAM_WRITE", authzData) {

		l.Warning.Printf("[DB] [PRJ-USER] The user [ %v ] is not allowed to add anyone to this project [ %v ]! \n", authzData[SEC_USER], destination)

		e = fmt.Errorf("user doesn't have enough permissions in this project - IAM_WRITE")

		state = statusForbidden

		return

	}

	tx := d.Db.Begin()

	if r := d.Db.Where(models.User{ID: user}).First(&u0).Error; !errors.Is(r, gorm.ErrRecordNotFound) {

		u.Projects = append(u0.Projects, destination.String())

		if e := tx.Model(u0).Updates(u).Error; e == nil {

			l.Info.Printf("[DB] [PRJ-USER] User [ %v ] correctly added to Project [ %v ] in the system.\n", u0.FirstName, destination)

			_, token := kclib.GetToken()

			if token != "" {

				_, perms := kclib.GetPermissionsFromRole("end_usr", prj.LinkedOrganization.String(), prj.ProjectShortName, destination.String())
				status := kclib.AddUserToProject(token, user.String(), destination.String(), prj.LinkedOrganization.String(), perms)

				if status.IsSuccess() {

					l.Info.Printf("[DB] [PRJ-USER] User [ %v ] added successfully to project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [PRJ-USER] User [ %v ] couldn't be added to project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to add user to organization in Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [PRJ-USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

				goto checkForFailure

			}

		} else {

			l.Warning.Printf("[DB] [PRJ-USER] Unable to add user [ %v ] to project [ %v ] in the system, check with administrator.\n", u0.FirstName, destination)

			state = statusFail

			goto checkForFailure

		}

	} else {

		l.Warning.Printf("[DB] [PRJ-USER] Unable to find the user [ %v ] in the system.\n", user)

		state = statusMissing

		return

	}

checkForFailure:

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

func (d *DbParameter) DeleteUserFromOrg(ctx context.Context, user, destination strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [ORG-USER] Attempting to remove user [ %v ] from organization [ %v ] now.\n", user, destination)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	var u0, u models.User
	var org models.Organization

	if e = d.Db.Where(models.Organization{ID: destination}).First(&org).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ-USER] Something went wrong when trying to retrieve the organization [ %v ]\n", destination)

		state = statusMissing

		return

	}

	if !d.isUserAllowed(destination.String(), "", "IAM_WRITE", authzData) {

		l.Warning.Printf("[DB] [ORG-USER] The user [ %v ] is not allowed to remove anyone from this organization [ %v ]! \n", authzData[SEC_USER], destination)

		e = fmt.Errorf("user doesn't have enough permissions in this organization - IAM_WRITE")

		state = statusForbidden

		return

	}

	tx := d.Db.Begin()

	if r := d.Db.Where(models.User{ID: user}).First(&u0).Error; !errors.Is(r, gorm.ErrRecordNotFound) {

		var isAllowed, isOwn bool

		for _, org := range u0.AllowedOrganizations {

			if org == destination.String() {

				isAllowed = true

				continue

			}

			u.AllowedOrganizations = append(u.AllowedOrganizations, org)

		}

		isOwn = (u0.OrganizationID == destination)

		if !isOwn && !isAllowed {

			l.Warning.Printf("[DB] [ORG-USER] The user [ %v ] is not linked to this organization [ %v ]! \n", user, destination)

			e = fmt.Errorf("user is not linked to this organization")

			state = statusFail

			return

		}

		if isOwn {

			if e := tx.Model(u0).Updates(map[string]interface{}{"organizationid": ""}).Error; e == nil {

				l.Info.Printf("[DB] [ORG-USER] User [ %v ] correctly removed from Organization [ %v ] in the system.\n", u0.FirstName, destination)

				_, token := kclib.GetToken()

				if token != "" {

					status := kclib.DeleteUserFromOrg(token, user.String(), destination.String())

					if status.IsSuccess() {

						l.Info.Printf("[DB] [ORG-USER] User [ %v ] removed successfully from Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

					} else {

						l.Warning.Printf("[DB] [ORG-USER] User [ %v ] couldn't be removed from Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

						e = fmt.Errorf("not able to remove user from organization in Keycloak - KC-lib")

						state = statusFail

						goto checkForFailure

					}

				} else {

					l.Warning.Printf("[DB] [ORG-USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

					e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [ORG-USER] Unable to remove user [ %v ] from organization [ %v ] in the system, check with administrator.\n", u0.FirstName, destination)

				state = statusFail

				goto checkForFailure

			}

		}

		if isAllowed {

			if e := tx.Model(u0).Updates(map[string]interface{}{"allowedorganizations": u.AllowedOrganizations}).Error; e == nil {

				l.Info.Printf("[DB] [ORG-USER] User [ %v ] correctly removed from Organization [ %v ] in the system.\n", u0.FirstName, destination)

				_, token := kclib.GetToken()

				if token != "" {

					status := kclib.DeleteUserFromOrg(token, user.String(), destination.String())

					if status.IsSuccess() {

						l.Info.Printf("[DB] [ORG-USER] User [ %v ] removed successfully from Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

					} else {

						l.Warning.Printf("[DB] [ORG-USER] User [ %v ] couldn't be removed from Organization [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

						e = fmt.Errorf("not able to remove user from organization in Keycloak - KC-lib")

						state = statusFail

						goto checkForFailure

					}

				} else {

					l.Warning.Printf("[DB] [ORG-USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

					e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [ORG-USER] Unable to remove user [ %v ] from organization [ %v ] in the system, check with administrator.\n", u0.FirstName, destination)

				state = statusFail

				goto checkForFailure

			}

		}

	} else {

		l.Warning.Printf("[DB] [ORG-USER] Unable to find the user [ %v ] in the system.\n", user)

		state = statusMissing

		return

	}

checkForFailure:

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}

func (d *DbParameter) DeleteUserFromPrj(ctx context.Context, user, destination strfmt.UUID) (state int, e error) {

	l.Trace.Printf("[DB] [PRJ-USER] Attempting to add user [ %v ] to project [ %v ] now.\n", user, destination)

	authzData := ctx.Value(restapi.AuthKey).(map[string]string)

	state = statusOK

	var u0, u models.User
	var prj models.Project

	if e = d.Db.Where(models.Project{ProjectID: destination}).First(&prj).Error; e != nil {

		l.Warning.Printf("[DB] [PRJ-USER] Something went wrong when trying to retrieve the project [ %v ]\n", destination)

		state = statusFail

		return

	}

	if !d.isUserAllowed(prj.LinkedOrganization.String(), "", "IAM_WRITE", authzData) {

		l.Warning.Printf("[DB] [PRJ-USER] The user [ %v ] is not allowed to add anyone to this project [ %v ]! \n", authzData[SEC_USER], destination)

		e = fmt.Errorf("user doesn't have enough permissions in this project - IAM_WRITE")

		state = statusForbidden

		return

	}

	tx := d.Db.Begin()

	if r := d.Db.Where(models.User{ID: user}).First(&u0).Error; !errors.Is(r, gorm.ErrRecordNotFound) {

		var isAllowed bool

		for _, prj := range u0.Projects {

			if prj == destination.String() {

				isAllowed = true

				continue

			}

			u.Projects = append(u.Projects, prj)

		}

		if !isAllowed {

			l.Warning.Printf("[DB] [ORG-USER] The user [ %v ] is not linked to this project [ %v ]! \n", user, destination)

			e = fmt.Errorf("user is not linked to this project")

			state = statusFail

			return

		}

		if e := tx.Model(u0).Updates(map[string]interface{}{"projects": u.Projects}).Error; e == nil {

			l.Info.Printf("[DB] [PRJ-USER] User [ %v ] correctly added to Project [ %v ] in the system.\n", u0.FirstName, destination)

			_, token := kclib.GetToken()

			if token != "" {

				status := kclib.DeleteUserFromProject(token, user.String(), destination.String())

				if status.IsSuccess() {

					l.Info.Printf("[DB] [PRJ-USER] User [ %v ] added successfully to project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

				} else {

					l.Warning.Printf("[DB] [PRJ-USER] User [ %v ] couldn't be added to project [ %v ] in Keycloak: [ %v ] - [ %v ]\n", user, destination, status.StatusCode, status.Message)

					e = fmt.Errorf("not able to add user to organization in Keycloak - KC-lib")

					state = statusFail

					goto checkForFailure

				}

			} else {

				l.Warning.Printf("[DB] [PRJ-USER] The interaction with Keycloak couldn't be stablished, please check with administrator\n")

				e = fmt.Errorf("not able to interact with Keycloak - KC-lib")

				state = statusFail

				goto checkForFailure

			}

		} else {

			l.Warning.Printf("[DB] [PRJ-USER] Unable to add user [ %v ] to project [ %v ] in the system, check with administrator.\n", u0.FirstName, destination)

			state = statusFail

			goto checkForFailure

		}

	} else {

		l.Warning.Printf("[DB] [PRJ-USER] Unable to find the user [ %v ] in the system.\n", user)

		state = statusMissing

		return

	}

checkForFailure:

	if state == statusFail {

		e = tx.Rollback().Error

	} else {

		e = tx.Commit().Error

	}

	return

}
