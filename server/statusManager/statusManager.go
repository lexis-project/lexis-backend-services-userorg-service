package statusManager

import (
	"context"
	"fmt"
	"time"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/status_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/go-openapi/runtime/middleware"
	"gitlab.com/cyclops-utilities/datamodels"
	l "gitlab.com/cyclops-utilities/logging"
)

// Array containing all the monitors in the subsystem with one monit per endpoint.
type monitor struct {
	db map[string]*monits
}

// monits or monitors, is a struct that contains the data about an API Endpoint
// tha is being monitored.
// Parameters:
// - last: string with the timestamp of the last update.
// - day: array for the 24h of the days containing the hits to the endpoint in
// during the last 24h.
// - BoT: int with the number of hits to the endpoint from the Beginning of Time,
// AKA since the service started.
type monits struct {
	last    string
	day     [24]int64
	BoT     int64
	AvgTime float64
}

// StatusManager is the struct defined to group and contain all the methods
// that interact with the status report subsystem.
// Parameters:
// - db: a DbParameter reference to be able to use the DBManager methods.
type StatusManager struct {
	db      *dbManager.DbParameter
	Service string
}

var (
	mon     monitor
	start   time.Time
	avgTime map[string]int64
)

// New is the function to create the struct StatusManager.
// Returns:
// - StatusManager: struct to interact with statusManager subsystem functionalities.
func New(db *dbManager.DbParameter) *StatusManager {

	l.Trace.Printf("[StatusManager] Generating new StatusManager.\n")

	g := monits{last: "System just started"}
	s := monits{last: "Status just started"}

	mon = monitor{
		db: make(map[string]*monits),
	}

	mon.db["main"] = &g
	mon.db["status"] = &s

	start = time.Now()

	avgTime = make(map[string]int64)

	return &StatusManager{Service: "User-Org Service", db: db}

}

// GetStatus (Swagger func) is the function behind the API Endpoint /status/{id}
// It give the current hit-status of the selected endpoint and a primitive
// system and db connection status report.
func (m *StatusManager) GetStatus(ctx context.Context, params status_management.GetStatusParams) middleware.Responder {

	l.Trace.Printf("[StatusManager] GetStatus endpoint invoked.\n")

	// Keycloak Syncing here
	go m.db.KeycloakSync()

	callTime := time.Now()
	m.APIHit("status", callTime)

	if _, ok := mon.db[params.ID]; !ok {

		missingReturn := models.ErrorResponse{
			Message: "The Status for the requested endpoint doesn't exists in the system.",
		}

		m.APIHitDone("status", callTime)

		return status_management.NewGetStatusNotFound().WithPayload(&missingReturn)

	}

	status := "Healthy"

	today := int64(0)

	for _, i := range mon.db[params.ID].day {

		today += i

	}

	stats := models.Status{
		AverageResponseTime: mon.db[params.ID].AvgTime,
		LastRequest:         mon.db[params.ID].last,
		RequestsBoT:         mon.db[params.ID].BoT,
		RequestsLastHour:    mon.db[params.ID].day[(time.Now()).Hour()],
		RequestsToday:       today,
		SystemState:         status,
	}

	m.APIHitDone("status", callTime)

	return status_management.NewGetStatusOK().WithPayload(&stats)

}

// ShowStatus (Swagger func) is the function behind the API Endpoint /status
// It give the current hit-status of the whole system and a primitive
// system and db connection status report.
func (m *StatusManager) ShowStatus(ctx context.Context, params status_management.ShowStatusParams) middleware.Responder {

	l.Trace.Printf("[StatusManager] ShowStatus endpoint invoked.\n")

	// Keycloak Syncing here
	go m.db.KeycloakSync()

	callTime := time.Now()
	m.APIHit("status", callTime)

	status := "Healthy"

	today := int64(0)

	for _, i := range mon.db["main"].day {

		today += i

	}

	endpoints := make(datamodels.JSONdb)

	for ep, m := range mon.db {

		if ep == "main" {

			continue

		}

		endpoints[ep] = m.AvgTime

	}

	stats := models.Status{
		AverageResponseTime:   mon.db["main"].AvgTime,
		EndpointsResponseTime: endpoints,
		LastRequest:           mon.db["main"].last,
		RequestsBoT:           mon.db["main"].BoT,
		RequestsLastHour:      mon.db["main"].day[(time.Now()).Hour()],
		RequestsToday:         today,
		SystemState:           status,
	}

	m.APIHitDone("status", callTime)

	return status_management.NewShowStatusOK().WithPayload(&stats)

}

// InitEndpoint is meant to be called on the New() functions representing each
// endpoint, its job is to initialize the endpoint index in the status array.
// Parameters:
// - index: string for identifying the endpoint. Should be unique per endpoint
// and contained in the enum list in the swagger file
func (m *StatusManager) InitEndpoint(index string) {

	l.Trace.Printf("[StatusManager] Initializing monitoring of endpoint: %v.\n", index)

	e := monits{

		last: index + " just started",
	}

	mon.db[index] = &e

}

// APIHit is meant to be called at the beginning of each endpoint function.
// Its job is to update the information about the last time that endpoint was
// called and the rest of the metrics for the endpoint in the subsystem.
// Parameters:
// - index: string for identifying the endpoint. Should be unique per endpoint
// and contained in the enum list in the swagger file
// - t: a time.Time timestamp with refering to the moment the endpoint was called.
func (m *StatusManager) APIHit(index string, t time.Time) {

	l.Debug.Printf("[StatusManager] Endpoint: %v, has been invoked.\n", index)

	limit, _ := time.ParseDuration("25h")
	cleanAllLimit, _ := time.ParseDuration("26h")
	difference := (time.Now()).Sub(start)

	if difference >= limit {

		if difference >= cleanAllLimit {

			m.cleanCount(25)

		} else {

			m.cleanCount(t.Hour() - 1)

		}

		start = time.Now()

	}

	// First we update the general count
	mon.db["main"].last = t.String()
	mon.db["main"].BoT++
	mon.db["main"].day[t.Hour()]++

	// Then we update the specific endpoint count
	mon.db[index].last = t.String()
	mon.db[index].BoT++
	mon.db[index].day[t.Hour()]++

	key := fmt.Sprintf("%v_%v", index, t.UnixNano())

	avgTime[key] = t.UnixNano()

	return

}

// APIHit is meant to be called right before the return of each endpoint function.
// Its job is to update the average time spent on the processing of each endpoint.
// Parameters:
// - index: string for identifying the endpoint. Should be unique per endpoint
// and contained in the enum list in the swagger file
// - t: a time.Time timestamp with refering to the moment the endpoint was called.
// Returns:
// - key: the key for avgTime map track.
func (m *StatusManager) APIHitDone(index string, t time.Time) {

	key := fmt.Sprintf("%v_%v", index, t.UnixNano())

	if previous, exists := avgTime[key]; exists {

		to := float64(time.Now().UnixNano())
		from := float64(previous)

		avg := float64((mon.db[index].AvgTime*float64(mon.db[index].day[t.Hour()]-1) + (to-from)/float64(time.Millisecond)) / float64(mon.db[index].day[t.Hour()]))
		avgSystem := float64((mon.db["main"].AvgTime*float64(mon.db["main"].day[t.Hour()]-1) + (to-from)/float64(time.Millisecond)) / float64(mon.db["main"].day[t.Hour()]))

		mon.db[index].AvgTime = avg
		mon.db["main"].AvgTime = avgSystem

		delete(avgTime, key)

	}

	return

}

// cleanCount 's job is to clean the day arrays on the subsystem.
// The logic behind it is that every 25h (or more) this function is called with
// a reference to previous hour cleaning setting the whole array to 0 except for
// that hour.
// Parameters:
// - h: integer for the hour to keep without cleaning.
func (m *StatusManager) cleanCount(h int) {

	for key := range mon.db {

		for idx := range mon.db[key].day {

			if idx != h {

				mon.db[key].day[idx] = 0

			}

		}

	}

	return

}
