package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	kclib "code.it4i.cz/lexis/wp4/keycloak-lib"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi"
	"github.com/Nerzal/gocloak/v9"
	"github.com/go-openapi/strfmt"
	l "gitlab.com/cyclops-utilities/logging"
)

const (
	SEC_API_KEY   = "KEY"
	SEC_ORG       = "ORG"
	SEC_PRJ       = "PRJ"
	SEC_NAME      = "SHORTNAME"
	SEC_ROLE      = "ROLE"
	SEC_USER      = "USER"
	SEC_TOKEN     = "TOKEN"
	CHECK_API_KEY = "API_KEY"
	CHECK_SELF    = "SELF_SERVICE"
	CHECK_ORG     = "OWN_ORG"
	CHECK_WORG    = "WRITE_ORG"
	CHECK_PRJ     = "OWN_PRJ"
	CHECK_WPRJ    = "WRITE_PRJ"
	ROLE_END_USER = "end_usr"
	NIL           = "00000000-0000-0000-0000-000000000000"
	ORG_ATT       = "org_read"
	PRJ_ATT       = "prj_list"
)

var (
	//roles = []string{"lex_adm", "lex_sup", "org_mgr", "prj_mgr", "dat_mgr", "end_usr"}
	roles = []string{"org_mgr", "prj_mgr", "dat_mgr", "end_usr"}
)

// getKeycloaktService returns the keycloak service; note that there has to be exceptional
// handling of port 80 and port 443
func getKeycloakService(c keycloakConfig) (s string) {

	if c.UseHTTP {

		s = "http://" + c.Host

		if c.Port != 80 {

			s = s + ":" + strconv.Itoa(c.Port)
		}

	} else {

		s = "https://" + c.Host

		if c.Port != 443 {

			s = s + ":" + strconv.Itoa(c.Port)

		}

	}

	return

}

// Authorizer (Swagger func) is called after validating the entry token to check
// if the access should be granted or not.
func Authorizer(req *http.Request) error {

	l.Debug.Printf("[AUTHORIZER] Performing authorization for endpoint [ %v ]\n", req.URL.Path)

	if !cfg.AuthzEnabled {

		l.Debug.Printf("[AUTHORIZER] Authz workflow is not enabled, skipping check.\n")

		return nil

	}

	var activePolicy *policy

	var pathID string

	method := req.Method
	path := req.URL.Path
	basePath := getBasePath()
	tokenData := req.Context().Value(restapi.AuthKey).(map[string]string)

	for i, pol := range cfg.Policies {

		if pol.Method != method {

			continue

		}

		probingkey := basePath + pol.Endpoint

		if matches, e := regexp.MatchString(probingkey, path); matches {

			pathIDs := strings.Split(path, "/")

			if len(pathIDs) > 1 {

				// More use cases to be added here when the ids are in the middle of the path instead of at the end...
				pathID = pathIDs[len(pathIDs)-1]

			}

			activePolicy = &cfg.Policies[i]

			break

		} else if e != nil {

			l.Warning.Printf("[AUTHORIZER] There was an error making the regex match of the path in the policy: Error: %v\n", e)

		}

	}

	if activePolicy == nil {

		l.Warning.Printf("[AUTHORIZER] Not able to find a matching policy for the entry attemp. REJECTING!\n")

		return errors.New("your attempt doesn't match any of the Authz policies")

	}

	// Meant to be used only with the /status endpoints, so the monitoring system doesn't have to bother with having a proper token
	if _, exists := tokenData[SEC_API_KEY]; exists && strings.Contains(strings.Join(activePolicy.Checks, " "), CHECK_API_KEY) {

		l.Warning.Printf("[AUTHORIZER] ATTENTION!!! Entry via api-token [ %v ]. AUTHORIZING!\n", path)

		return nil

	}

	if !strings.Contains(strings.Join(activePolicy.Allowed, " "), tokenData[SEC_ROLE]) {

		l.Warning.Printf("[AUTHORIZER] The role doesn't match the allowed by the policy. REJECTING!\n")

		return errors.New("your role doesn't match any of the allowed ones by the Authz policy")

	}

	for _, check := range activePolicy.Checks {

		l.Debug.Printf("[AUTHORIZER] Extra checks found, starting the processing...\n")

		switch check {

		case CHECK_SELF:
			{

				if tokenData[SEC_ROLE] != ROLE_END_USER {

					continue

				}

				if tokenData[SEC_USER] != pathID {

					l.Warning.Printf("[AUTHORIZER] The end user is trying to check/update a different id than its own. REJECTING!\n")

					return errors.New("you do not have permission over this user")

				}

			}

		case CHECK_ORG:
			{

				if pathID == "" || (pathID != NIL && strings.Contains(tokenData[SEC_ORG], pathID)) {

					continue

				}

				l.Warning.Printf("[AUTHORIZER] Trying to interact with an organization not allowed by the token. REJECTING!\n")

				return errors.New("you do not have permission to read or delete this organization")

			}

		case CHECK_PRJ:
			{

				if pathID == "" || (pathID != NIL && strings.Contains(tokenData[SEC_PRJ], pathID)) {

					continue

				}

				l.Warning.Printf("[AUTHORIZER] Trying to interact with a project not allowed by the token. REJECTING!\n")

				return errors.New("you do not have permission to read or delete this project")

			}

		case CHECK_WORG:
			{

				if tokenData["ORG_WRITE"] != "" && pathID != NIL && strings.Contains(tokenData["ORG_WRITE"], pathID) {

					continue

				}

				l.Warning.Printf("[AUTHORIZER] Trying to write to an organization not allowed by the token. REJECTING!\n")

				return errors.New("you do not have write permission for this organization")

			}

		case CHECK_WPRJ:
			{

				if tokenData["PRJ_WRITE"] != "" && pathID != NIL && strings.Contains(tokenData["PRJ_WRITE"], pathID) {

					continue

				}

				l.Warning.Printf("[AUTHORIZER] Trying to write to an organization not allowed by the token. REJECTING!\n")

				return errors.New("you do not have write permission for this project")

			}

		}

	}

	l.Info.Printf("[AUTHORIZER] We didn't found any mismatch in the policy. AUTHORIZING!\n")

	return nil

}

// AuthKeycloak (Swagger func) is called whenever it is necessary to check if a
// token which is presented to access an API is valid.
func AuthKeycloak(token string, scopes []string) (i interface{}, returnError error) {

	l.Debug.Printf("[KEYCLOAK] Performing authentication check. Scopes [ %v ] - Token [ ****%v... ]\n", scopes, token[:13])

	if !cfg.Keycloak.Enabled {

		returnError = errors.New("the Keycloak authentication is not active in this deployment")

		return

	}

	keycloakService := getKeycloakService(cfg.Keycloak)
	client := gocloak.NewClient(keycloakService)
	ctx := context.Background()

	_, e := client.LoginClient(ctx, cfg.Keycloak.ClientID, cfg.Keycloak.ClientSecret, cfg.Keycloak.Realm)

	if e != nil {

		l.Warning.Printf("[KEYCLOAK] Problems logging into keycloak. Error: %v\n", e)
		returnError = errors.New("unable to log in to keycloak")

		return

	}

	retroinspection, e := client.RetrospectToken(ctx, token, cfg.Keycloak.ClientID, cfg.Keycloak.ClientSecret, cfg.Keycloak.Realm)

	if e != nil {

		l.Warning.Printf("[KEYCLOAK] Problems retroinspecting the token. Error: %v\n", e)
		returnError = errors.New("unable to retroinspect the token")

		return

	}

	if !*retroinspection.Active {

		l.Warning.Printf("[KEYCLOAK] The token seems to be no longer valid. Token Active State: %v\n", *retroinspection.Active)
		returnError = errors.New("token no longer valid")

		return

	}

	attributes, e := client.GetRawUserInfo(ctx, token, cfg.Keycloak.Realm)

	if e != nil {

		l.Warning.Printf("[KEYCLOAK] Problems retrieving the user info. Error: %v\n", e)
		returnError = errors.New("unable to get the user info")

		return

	}

	r := make(map[string]string)

	r[SEC_TOKEN] = token

	// NIL everything as default
	r[SEC_USER] = NIL
	r[SEC_ORG] = NIL
	r[SEC_PRJ] = NIL
	r[SEC_NAME] = NIL

	// end_usr for default role
	r[SEC_ROLE] = roles[len(roles)-1]

	if attributes["sub"] != nil {

		r[SEC_USER] = attributes["sub"].(string)

	}

	if attributes["attributes"] != nil {

		//l.Warning.Printf("[KC<->UO] Attributes received from Keycloak for the user: %+v\n", attributes["attributes"])

		r[SEC_ORG], r[SEC_PRJ], r[SEC_NAME] = getIDs(attributes["attributes"].(map[string]interface{}))
		r[SEC_ROLE] = getRole(attributes["attributes"].(map[string]interface{}), r[SEC_ORG], r[SEC_PRJ])
		r = getPermissions(r, attributes["attributes"].(map[string]interface{}))

	} else {

		l.Warning.Printf("[AUTHZ] The user attributes from Keycloak are nil, if this is not a newly created user then there's something wrong with Keycloak!\n")
		// Workaround for the users that have just been added
		//returnError = errors.New("user attributes from Keycloak are nil")

		// return

	}

	i = r

	return

}

// getIDs job is to parse the attributes received from Keycloak and extract the
// ORG and PRJ UUIDs.
// The design assumes that the first UUID tha matches the attributes is the only
// one around and doesn't double check.
func getIDs(att map[string]interface{}) (org, prj, sn string) {

	prjs := make(map[string]int)
	orgs := make(map[string]int)
	sns := make(map[string]int)

	org = NIL
	prj = NIL
	sn = NIL

	attArray, exists := att[PRJ_ATT].([]interface{})

	if exists {

		for i := range attArray {

			attMap, exists := attArray[i].(map[string]interface{})

			if exists {

				//orgs[attMap["ORG_UUID"].(string)]++
				prjs[attMap["PRJ_UUID"].(string)]++
				sns[attMap["PRJ"].(string)]++

			}

		}

	}

	attArray, exists = att[ORG_ATT].([]interface{})

	if exists {

		for i := range attArray {

			attMap, exists := attArray[i].(map[string]interface{})

			if exists {

				orgs[attMap["ORG_UUID"].(string)]++

			}
		}

	}

	if len(orgs) > 0 {

		keys := make([]string, len(orgs))

		i := 0

		for k := range orgs {

			keys[i] = k

			i++

		}

		sort.Strings(keys)

		org = strings.Join(keys, " ")

	}

	if len(prjs) > 0 {

		keys := make([]string, len(prjs))

		i := 0

		for k := range prjs {

			keys[i] = k

			i++

		}

		sort.Strings(keys)

		prj = strings.Join(keys, " ")

	}

	if len(sns) > 0 {

		keys := make([]string, len(sns))

		i := 0

		for k := range sns {

			keys[i] = k

			i++

		}

		sort.Strings(keys)

		sn = strings.Join(keys, " ")

	}

	return

}

func getRole(att map[string]interface{}, orgs, prjs string) string {

	at := make(map[string][]string)
	pickRole := make(map[string]int)

	var prj string

	for v, k := range att {

		var b [][]string

		for _, m := range k.([]interface{}) {

			for r, i := range m.(map[string]interface{}) {

				var a []string

				a = append(a, strings.ToUpper(r))
				a = append(a, i.(string))

				b = append(b, a)

			}

		}

		at[strings.ToUpper(v)] = []string{createJsonOfAttributes(b)}

	}

	for _, org := range strings.Fields(orgs) {

		for _, p := range strings.Fields(prjs) {

			for _, role := range roles {

				if p != NIL {

					prj = p

				}

				if kclib.CheckAccess(at, role, org, prj) {

					pickRole[role]++

				}

			}

		}

	}

	for i := 0; i < len(roles); i++ {

		if _, exists := pickRole[roles[i]]; exists {

			return roles[i]

		}

	}

	return roles[len(roles)-1]

}

// getPermissions extracts the permissions form the attributes into a more usable
// set of value in a map[string]string that is passed by the context further
// into the service.
func getPermissions(store map[string]string, atts map[string]interface{}) map[string]string {

	for perm := range atts {

		attArray, exists := atts[perm].([]interface{})

		var values []string

		if exists {

			for i := range attArray {

				attMap, exists := attArray[i].(map[string]interface{})

				if exists {

					org, orgExists := attMap["ORG_UUID"]
					prj, prjExists := attMap["PRJ_UUID"]

					if orgExists && prjExists && (strfmt.IsUUID(org.(string)) && strfmt.IsUUID(prj.(string))) {

						values = append(values, org.(string)+"/"+prj.(string))

					} else if orgExists && strfmt.IsUUID(org.(string)) {

						values = append(values, org.(string))

					} else if prjExists && strfmt.IsUUID(prj.(string)) {

						values = append(values, prj.(string))

					}

				}

			}

			store[strings.ToUpper(perm)] = strings.Join(values, ",")

		}

	}

	return store

}

// AuthAPIKey (Swagger func) assures that the token provided when connecting to
// the API is the one presented in the config file as the valid token for the
// deployment.
func AuthAPIKey(token string) (i interface{}, e error) {

	l.Warning.Printf("[APIKey] Trying entry with key [ ***%v ]\n", token[:4])

	if !cfg.APIKey.Enabled {

		e = errors.New("the API Key authentication is not active in this deployment")

		return

	}

	if cfg.APIKey.Token == token {

		r := make(map[string]string)

		r[SEC_API_KEY] = token

		// NIL everything as default
		r[SEC_USER] = NIL
		r[SEC_ORG] = NIL
		r[SEC_PRJ] = NIL
		r[SEC_NAME] = NIL

		// end_usr for default role
		r[SEC_ROLE] = roles[len(roles)-1]

		i = r

	} else {

		e = errors.New("provided token is not valid")

	}

	return

}

func createJsonOfAttributes(attributes [][]string) string {

	var res = "{"

	for index, attribute := range attributes {

		res = res + "\"" + attribute[0] + "\":\"" + attribute[1] + "\""

		if index < len(attributes)-1 {

			res += ","

		}

	}

	res += "}"

	return res

}
