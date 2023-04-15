package main

import (
	"os"
	"fmt"
	"time"
	"bytes"
	"strconv"
	"io/ioutil"
	"encoding/json"
	"net/http"


	"github.com/gorilla/websocket"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/thoro/log"
)

// METRICS
var (
    battery_percent = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "battery_percent",
    	Help: "Current battery status in percent",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    connected = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "connected",
    	Help: "Connection status of the automower",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    last_update = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "last_update",
    	Help: "Unix timestamp of the last automower update",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    activity = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "activity",
    	Help: "Current mower activity",
    }, []string{
    	"serial",
    	"name",
    	"model",
    	"activity",
    })

    mode = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "mode",
    	Help: "Current mower mode",
    }, []string{
    	"serial",
    	"name",
    	"model",
    	"mode",
    })

    state = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "state",
    	Help: "Current mower state",
    }, []string{
    	"serial",
    	"name",
    	"model",
    	"state",
    })

    next_start = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "next_start",
    	Help: "Unix timestamp of the next automower start",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    cutting_height = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "cutting_height",
    	Help: "Current cutting height",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    blade_usage_time = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "blade_usage_time",
    	Help: "Total time for blade usage",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    charging_time = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "charging_time",
    	Help: "Total time charging",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    cutting_time = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "cutting_time",
    	Help: "Total time cutting",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    running_time = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "running_time",
    	Help: "Total time running",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    searching_time = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "searching_time",
    	Help: "Total time searching",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    charging_cycles = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "charging_cycles",
    	Help: "Number of charging cycles",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    collisions = promauto.NewGaugeVec(prometheus.GaugeOpts{
    	Namespace: "mower",
    	Name: "collisions",
    	Help: "Number of collisions",
    }, []string{
    	"serial",
    	"name",
    	"model",
    })

    api_requests_used = promauto.NewCounterVec(prometheus.CounterOpts{
    	Namespace: "mower",
    	Name: "api_requests_users",
    	Help: "Number of api requests since start"
    }, []string{
    	"client_id",
    })
)

func main() {
	// Read config values from env vars and log errors if not available

	clientId := os.Getenv("HUSQVARNA_CLIENT_ID")
	clientSecret := os.Getenv("HUSQVARNA_CLIENT_SECRET")

	if clientId == "" {
		log.Errorf("HUSQVARNA_CLIENT_ID is not set - exiting")
		os.Exit(1)
	}

	if clientSecret == "" {
		log.Errorf("HUSQVARNA_CLIENT_SECRET is not set - exiting")
		os.Exit(1)
	}

	h := NewHusqvarna(clientId, clientSecret)

	// Startup webserver
	http.Handle("/metrics", promhttp.Handler())

	go func () {
		err := http.ListenAndServe(":2118", nil)

		if err != nil {
			log.Errorf("Unable to serve metrics: %s", err)
			os.Exit(1)
		}
	}()

	err := h.Login()

	if err != nil {
		log.Errorf("Error on login: %v", err)
		os.Exit(1)
	}

	// Update mowers

	go func () {
		t := time.NewTicker(30 * time.Second)

		for {
			select {
			case <-t.C:
				if h.Token.ExpiresAt.Before(time.Now()) {
					err := h.Login()

					if err != nil {
						log.Errorf("Error on login: %v", err)
						continue
					}
				}

				resp, err := h.Mowers()

				if err != nil {
					log.Errorf("Error loading mower info: %v", err)
					continue
				}

				lastUpdate := time.Now()
				all_asleep := true

				// fill metrics
				for _, mower := range resp.Data {
					serial := strconv.Itoa(mower.Attributes.System.SerialNumber)
					name := mower.Attributes.System.Name
					model := mower.Attributes.System.Model

					battery_percent.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Battery.Percent))
					connectedVal := 0.0

					if mower.Attributes.Metadata.Connected {
						connectedVal = 1.0
					}

					connected.WithLabelValues(serial, name, model).Set(connectedVal)
					last_update.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Metadata.StatusTimestamp))

					mw_update := time.Unix(int64(mower.Attributes.Metadata.StatusTimestamp) / 1000, 0)

					log.Infof("Last update: %v", mw_update)

					if lastUpdate.After(mw_update) {
						lastUpdate = mw_update
					}

					if mower.Attributes.Mower.Activity == "IN_OPERATION" {
						all_asleep = false
					}

					for _, a := range ACTIVITIES {
						if a == mower.Attributes.Mower.Activity {
							activity.WithLabelValues(serial, name, model, a).Set(1)
						} else {
							activity.WithLabelValues(serial, name, model, a).Set(0)
						}
					}

					for _, a := range MODES {
						if a == mower.Attributes.Mower.Mode {
							mode.WithLabelValues(serial, name, model, a).Set(1)
						} else {
							mode.WithLabelValues(serial, name, model, a).Set(0)
						}
					}

					for _, a := range STATES {
						if a == mower.Attributes.Mower.State {
							state.WithLabelValues(serial, name, model, a).Set(1)
						} else {
							state.WithLabelValues(serial, name, model, a).Set(0)
						}
					}

					next_start.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Planner.NextStartTimestamp))
					cutting_height.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Settings.CuttingHeight))
					blade_usage_time.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.CuttingBladeUsageTime))
					charging_time.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.TotalChargingTime))
					cutting_time.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.TotalCuttingTime))
					running_time.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.TotalRunningTime))
					searching_time.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.TotalSearchingTime))
					charging_cycles.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.NumberOfChargingCycles))
					collisions.WithLabelValues(serial, name, model).Set(float64(mower.Attributes.Statistics.NumberOfCollisions))
				}

				time_since_last_update := time.Now().Sub(lastUpdate)

				if time_since_last_update.Seconds() > 60 {
					t.Reset(60 * time.Second)
					log.Infof("Resetting timer to 60 seconds")

					if all_asleep {
						t.Reset(600 * time.Second)
						log.Infof("Resetting timer to 600 seconds")
					}

				} else {
					t.Reset(30 * time.Second)
					log.Infof("Resetting timer to 30 seconds")
				}


			}
		}
	}()


	c, _, err := websocket.DefaultDialer.Dial("wss://ws.openapi.husqvarna.dev/v1", http.Header{ "Authorization": []string{ "Bearer " + h.Token.AccessToken} })

	if err != nil {
		log.Errorf("Error connecting to websocket!")
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Infof("read:", err)
				return
			}
			log.Infof("recv: %s", message)
		}
	}()

	go func () {
		t := time.NewTicker(60 * time.Second)

		for {
			select {
			case <-t.C:
				err := c.WriteControl(websocket.PingMessage, nil, time.Time{})
				if err != nil {
					log.Errorf("Error writing control: %v", err)
				}
			}
		}
	}()

	<-done

}

var (
	MODES = []string{ "MAIN_AREA", "SECONDARY_AREA", "HOME", "DEMO", "UNKNOWN" }
	ACTIVITIES = []string{ "UNKNOWN", "NOT_APPLICABLE", "MOWING", "GOING_HOME", "CHARGING", "LEAVING", "PARKED_IN_CS", "STOPPED_IN_GARDEN" }
	STATES = []string{ "UNKNOWN", "NOT_APPLICABLE", "PAUSED", "IN_OPERATION", "WAIT_UPDATING", "WAIT_POWER_UP", "RESTRICTED", "OFF", "STOPPED", "ERROR", "FATAL_ERROR", "ERROR_AT_POWER_UP" }
)

var (
	LOGIN_URL = "https://api.authentication.husqvarnagroup.dev/v1"
	API_URL = "https://api.amc.husqvarna.dev/v1"
)

type Husqvarna struct {
	ClientId string
	ClientSecret string
	Token Token
}

type Token struct {
	AccessToken string `json:"access_token"`
	Scope string `json:"scope"`
	ExpiresIn int `json:"expires_in"`
	ExpiresAt time.Time
	Provider string `json:"provider"`
	UserId string `json:"user_id"`
	TokenType string `json:"token_type"`
}

type MowersResponse struct {
	Data []Mower `json:"data"`
	Errors []Error `json:"errors"`
}

type Mower struct {
	Type string `json:"type"`
	Id string `json:"id"`
	Attributes Attributes `json:"attributes"`
}

type Attributes struct {
	System System `json:"system"`
	Battery Battery `json:"battery"`
	Mower MowerData `json:"mower"`
	Calendar Calendar `json:"calendar"`
	Planner Planner `json:"planner"`
	Metadata Metadata `json:"metadata"`
	Positions []Position `json:"positions"`
	Settings Settings `json:"settings"`
	Statistics Statistics `json:"statistics"`
}

type System struct {
	Name string `json:"name"`
	Model string `json:"model"`
	SerialNumber int `json:"serialNumber"`
}

type Battery struct {
	Percent int `json:"batteryPercent"`
}

type MowerData struct {
	Mode string `json:"mode"`
	Activity string `json:"activity"`
	State string `json:"state"`
	ErrorCode int `json:"errorCode"`
	ErrorCodeTimestamp int `json:"errorCodeTimestamp"`
}

type Calendar struct {
	Tasks []Task `json:"tasks"`
}

type Task struct {
	Start int `json:"start"`
	Duration int `json:"duration"`
	Monday bool `json:"monday"`
	Tuesday bool `json:"tuesday"`
	Wednesday bool `json:"wednesday"`
	Thursday bool `json:"thursday"`
	Friday bool `json:"friday"`
	Saturday bool `json:"saturday"`
	Sunday bool `json:"sunday"`
}

type Planner struct {
	NextStartTimestamp int `json:"nextStartTimestamp"`
	Override Action `json:"override"`
	RestricedReason string `json:"restrictedReason"`
}

type Action struct {
	Action string `json:"action"`
}

type Metadata struct {
	Connected bool `json:"connected"`
	StatusTimestamp int `json:"statusTimestamp"`
}

type Position struct {
	Latitude float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type Settings struct {
	CuttingHeight int `json:"cuttingHeight"`
	Headlight Headlight `json:"headlight"`
}

type Headlight struct {
	Mode string `json:"mode"`
}

type Statistics struct {
	CuttingBladeUsageTime int `json:"cuttingBladeUsageTime"`
	NumberOfChargingCycles int `json:"numberOfChargingCycles"`
	NumberOfCollisions int `json:"numberOfCollisions"`
	TotalChargingTime int `json:"totalChargingTime"`
	TotalCuttingTime int `json:"totalCuttingTime"`
	TotalRunningTime int `json:"totalRunningTime"`
	TotalSearchingTime int `json:"totalSearchingTime"`
}

type Error struct {
	Id string `json:"id"`
	Status string `json:"status"`
	Code string `json:"code"`
	Title string `json:"title"`
	Detail string `json:"detail"`
}

func NewHusqvarna(clientId, clientSecret string) *Husqvarna {
	return &Husqvarna{
		ClientId: clientId,
		ClientSecret: clientSecret,
	}
}

func (h *Husqvarna) Login() error {

	client := getClient()

	req, err := http.NewRequest("POST", LOGIN_URL + "/oauth2/token", bytes.NewBuffer([]byte(fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s", h.ClientId, h.ClientSecret))))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		return fmt.Errorf("Login/CreateRequest: %w", err)
	}

	resp, err := client.Do(req)

	if err != nil {
		return fmt.Errorf("Login/DoRequest: %w", err)
	}

	if resp.StatusCode != 200 {
		content, _ := ioutil.ReadAll(resp.Body)

		return fmt.Errorf("Login/StatusCode: Request was not successful: %d %s", resp.StatusCode, content)
	}

	var token Token

	json.NewDecoder(resp.Body).Decode(&token)

	h.Token = token
	h.Token.ExpiresAt = time.Now().Add(time.Duration(h.Token.ExpiresIn - 1000) * time.Second)

	return nil
}

func (h *Husqvarna) Mowers() (*MowersResponse, error) {
	data, err := h.queryGet(API_URL + "/mowers", 200)

	if err != nil {
		return nil, err
	}

	var resp *MowersResponse

	err = json.Unmarshal(data, &resp)

	return resp, err
}

func getClient() *http.Client {
	return &http.Client{
		Timeout: time.Second * 60,
	}
}

func (h *Husqvarna) query(method, url string, expected int, req_content []byte) ([]byte, error) {
	client := getClient()

	req, err := http.NewRequest(method, url, bytes.NewBuffer(req_content))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization-Provider", h.Token.Provider)
	req.Header.Set("X-Api-Key", h.ClientId)
	req.Header.Add("Authorization", "Bearer " + h.Token.AccessToken)

	api_requests_used.WithLabelValues(h.ClientId).Inc()

	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("Unable to send request: %w", err.Error())
	}

	res_content, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != expected {
		return res_content, fmt.Errorf("Request was not successful: %w, %s", resp.StatusCode, string(res_content))
	}

	return res_content, nil
}

func (h *Husqvarna) queryPost(url string, expected int, content []byte) ([]byte, error) {
	return h.query("POST", url, expected, content)
}

func (h *Husqvarna) queryGet(url string, expected int) ([]byte, error) {
	return h.query("GET", url, expected, []byte{})
}

