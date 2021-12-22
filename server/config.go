package main

import (
	"encoding/csv"
	"os"
	"strings"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/segmentio/encoding/json"
	"github.com/spf13/viper"
	l "gitlab.com/cyclops-utilities/logging"
)

// The following structs: keycloakConfig, apiKey, generalConfig, dbConfig,
// and kafkaConfig, are part of the configuration struct which acts as the main
// reference for configuration parameters in the system.
type keycloakConfig struct {
	Enabled      bool   `json:"enabled"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Realm        string `json:"realm"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	UseHTTP      bool   `json:"use_http"`
	RedirectURL  string `json:"redirect_url"`
}

type apiKey struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
}

type generalConfig struct {
	LogFile         string
	LogToConsole    bool
	LogLevel        string
	ServerPort      int
	HTTPSEnabled    bool   `json:"https_enabled"`
	CertificateFile string `json:"certificate_file"`
	CertificateKey  string `json:"certificate_key"`
}

type dbConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	SslModeOn bool
	DbName    string
}

type configuration struct {
	General      generalConfig
	DB           dbConfig
	Keycloak     keycloakConfig `json:"keycloak"`
	APIKey       apiKey
	PoliciesFile string
	Policies     []policy
	AuthzEnabled bool
}

type policy struct {
	Endpoint string
	Method   string
	Allowed  []string
	Checks   []string
}

// parsePolicies handles the filling of the config struct that contains the authz
// policies that the service will enforce for any entry/call.
// Returns:
// - pols: and array of policies
func parsePolicies() (policies []policy) {

	policyFile, e := os.Open(cfg.PoliciesFile)

	if e != nil {

		panic("Authz policy file couldn't be found\n")

	}

	r := csv.NewReader(policyFile)
	r.Comma = '|'
	r.Comment = '-'
	r.TrimLeadingSpace = true

	policiesList, e := r.ReadAll()

	if e != nil {

		panic("Authz policy file couldn't be readed\n")

	}

	for _, pol := range policiesList {

		newPolicy := policy{
			Endpoint: strings.TrimSpace(pol[0]),
			Method:   strings.TrimSpace(pol[1]),
			Allowed:  strings.Fields(pol[2]),
			Checks:   strings.Fields(pol[3]),
		}

		policies = append(policies, newPolicy)

	}

	return

}

// parseConfig handles the filling of the config struct with the data Viper gets
// from the configuration file.
// Returns:
// - c: the configuration struct filled with the relevant parsed configuration.
func parseConfig() (c configuration) {

	c = configuration{

		General: generalConfig{
			LogFile:         viper.GetString("general.logfile"),
			LogToConsole:    viper.GetBool("general.logtoconsole"),
			LogLevel:        viper.GetString("general.loglevel"),
			ServerPort:      viper.GetInt("general.serverport"),
			HTTPSEnabled:    viper.GetBool("general.httpsenabled"),
			CertificateFile: viper.GetString("general.certificatefile"),
			CertificateKey:  viper.GetString("general.certificatekey"),
		},

		DB: dbConfig{
			Host:      viper.GetString("database.host"),
			Port:      viper.GetInt("database.port"),
			Username:  viper.GetString("database.username"),
			Password:  viper.GetString("database.password"),
			SslModeOn: viper.GetBool("database.sslmodeon"),
			DbName:    viper.GetString("database.dbname"),
		},

		Keycloak: keycloakConfig{
			Enabled:      viper.GetBool("keycloak.enabled"),
			Host:         viper.GetString("keycloak.host"),
			Port:         viper.GetInt("keycloak.port"),
			Realm:        viper.GetString("keycloak.realm"),
			ClientID:     viper.GetString("keycloak.clientid"),
			ClientSecret: viper.GetString("keycloak.clientsecret"),
			UseHTTP:      viper.GetBool("keycloak.usehttp"),
			RedirectURL:  viper.GetString("keycloak.redirecturl"),
		},

		APIKey: apiKey{
			Enabled: viper.GetBool("apikey.enabled"),
			Token:   viper.GetString("apikey.token"),
		},

		PoliciesFile: viper.GetString("authz.policiesfile"),
		AuthzEnabled: viper.GetBool("authz.authzenabled"),
	}

	return

}

// getDBKeycloak creates a copy of the Keycloak config into the struct model
// for the dbManager so it can deal with Keycloak user administration.
func getDBKeycloak() dbManager.KeycloakConfig {

	return dbManager.KeycloakConfig{
		Enabled:      cfg.Keycloak.Enabled,
		Host:         cfg.Keycloak.Host,
		Port:         cfg.Keycloak.Port,
		Realm:        cfg.Keycloak.Realm,
		ClientID:     cfg.Keycloak.ClientID,
		ClientSecret: cfg.Keycloak.ClientSecret,
		UseHTTP:      cfg.Keycloak.UseHTTP,
		RedirectURL:  cfg.Keycloak.RedirectURL,
	}

}

// masked 's job is to return asterisks in place of the characters in a
// string with the exception of the last indicated.
// Parameters:
// - s: string to be masked
// - unmaskedChars: int with the amount (counting from the end of the string) of
// characters to keep unmasked.
// Returns:
// - returnString: the s string passed as parameter masked.
func masked(s string, unmaskedChars int) (returnString string) {

	if len(s) <= unmaskedChars {

		returnString = s

		return

	}

	asteriskString := strings.Repeat("*", (len(s) - unmaskedChars))
	returnString = asteriskString + string(s[len(s)-unmaskedChars:])

	return

}

// dumpConfig 's job is to dumps the configuration in JSON format to the log
// system. It makes use of the masking function to keep some secrecy in the log.
// Parameters:
// - c: configuration type containing the config present in the system.
func dumpConfig(c configuration) {
	cfgCopy := c

	// deal with configuration params that should be masked
	cfgCopy.DB.Password = masked(c.DB.Password, 4)
	cfgCopy.Keycloak.ClientSecret = masked(c.Keycloak.ClientSecret, 4)
	cfgCopy.APIKey.Token = masked(c.APIKey.Token, 4)

	// mmrshalindent creates a string containing newlines; each line starts with
	// two spaces and two spaces are added for each indent...
	configJSON, _ := json.MarshalIndent(cfgCopy, "  ", "  ")

	l.Info.Printf("Configuration settings:\n")
	l.Info.Printf("%v\n", string(configJSON))

}
