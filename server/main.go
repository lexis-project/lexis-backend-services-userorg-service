package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	kclib "code.it4i.cz/lexis/wp4/keycloak-lib"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/accessManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/hpcManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/organizationManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/projectManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/statusManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/userManager"
	"github.com/segmentio/encoding/json"
	"github.com/spf13/viper"
	l "gitlab.com/cyclops-utilities/logging"
)

var (
	cfg     configuration
	version string
)

// getBasePath function is to get the base URL of the server.
// Returns:
// - String with the value of the base URL of the server.
func getBasePath() string {

	type jsonBasePath struct {
		BasePath string
	}

	bp := jsonBasePath{}

	e := json.Unmarshal(restapi.SwaggerJSON, &bp)

	if e != nil {

		l.Warning.Printf("Unmarshalling of the basepath failed: %v\n", e)

	}

	return bp.BasePath

}

// dbStart handles the initialization of the dbManager returning a pointer to
// the DbParameter to be able to use the dbManager methods.
// Parameters:
// - models: variadic interface{} containing all the models that need to be
// migrated to the db.
// Returns:
// - DbParameter reference.
func dbStart(c dbManager.KeycloakConfig, models ...interface{}) *dbManager.DbParameter {

	var sslMode string

	if cfg.DB.SslModeOn {

		sslMode = "enable"

	} else {

		sslMode = "disable"

	}

	connStr := "user=" + cfg.DB.Username + " password=" + cfg.DB.Password +
		" dbname=" + cfg.DB.DbName + " sslmode=" + sslMode +
		" host=" + cfg.DB.Host + " port=" + strconv.Itoa(cfg.DB.Port)

	return dbManager.New(c, connStr, models...)

}

func init() {

	confFile := flag.String("conf", "./config", "configuration file path (without toml extension)")

	flag.Parse()

	//placeholder code as the default value will ensure this situation will never arise
	if len(*confFile) == 0 {

		fmt.Printf("Usage: UserOrgService -conf=/path/to/configuration/file\n")

		os.Exit(0)

	}

	// err := gcfg.ReadFileInto(&cfg, *confFile)
	viper.SetConfigName(*confFile) // name of config file (without extension)
	viper.SetConfigType("toml")
	viper.AddConfigPath(".") // path to look for the config file in

	err := viper.ReadInConfig() // Find and read the config file

	if err != nil {

		// TODO(murp) - differentiate between file not found and formatting error in
		// config file)
		fmt.Printf("Failed to parse configuration data: %s\nCorrect usage: UserOrgService -conf=/path/to/configuration/file\n", err)

		os.Exit(1)

	}

	cfg = parseConfig()

	cfg.Policies = parsePolicies()

	e := l.InitLogger(cfg.General.LogFile, cfg.General.LogLevel, cfg.General.LogToConsole)

	if e != nil {

		fmt.Printf("Initialization of the logger failed: %v\n", e)

	}

	l.Info.Printf("Cyclops Labs UserOrgService Manager version %v initialized\n", version)

	dumpConfig(cfg)

	l.Info.Printf("Initilizing Keycloak Lib...")

	kclib.InitLib("config_keycloak.toml")

}

func main() {

	// TABLE0,1,n have to be customized
	db := dbStart(getDBKeycloak(), &models.User{}, &models.Organization{}, &models.Project{}, &models.HPCResource{})
	mon := statusManager.New(db)

	bp := getBasePath()

	// Parts of the service HERE
	u := userManager.New(db, mon, bp)
	o := organizationManager.New(db, mon, bp)
	p := projectManager.New(db, mon, bp)
	hp := hpcManager.New(db, mon, bp)
	a := accessManager.New(db, mon, bp)

	// Initiate the http handler, with the objects that are implementing the business logic.
	h, err := restapi.Handler(restapi.Config{
		StatusManagementAPI:       mon,
		UserManagementAPI:         u,
		OrganizationManagementAPI: o,
		ProjectManagementAPI:      p,
		HpcManagementAPI:          hp,
		AccessManagementAPI:       a,
		Logger:                    l.Info.Printf,
		AuthKeycloak:              AuthKeycloak,
		AuthAPIKeyHeader:          AuthAPIKey,
		AuthAPIKeyParam:           AuthAPIKey,
		Authorizer:                Authorizer,
	})

	if err != nil {

		log.Fatal(err)

	}

	serviceLocation := ":" + strconv.Itoa(cfg.General.ServerPort)

	if cfg.General.HTTPSEnabled {

		c := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
		}
		srv := &http.Server{
			Addr:         serviceLocation,
			Handler:      h,
			TLSConfig:    c,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}

		log.Println("Starting to serve, access server on https://localhost" + serviceLocation)

		log.Fatal(srv.ListenAndServeTLS(cfg.General.CertificateFile, cfg.General.CertificateKey))

	} else {

		log.Println("Starting to serve, access server on http://localhost" + serviceLocation)

		// Run the standard http server
		log.Fatal(http.ListenAndServe(serviceLocation, h))

	}

}
