/**
 * @package   ShellyDiscovery
 * @copyright Thorsten Eurich
 * @license   GNU Affero General Public License (https://www.gnu.org/licenses/agpl-3.0.de.html)
 *
 * @todo lots of documentation
 *
 *
 * mDNS discovery for Shelly IoT-Devices
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/jasonlvhit/gocron"
)

type DeviceStatus struct {
	WifiSta struct {
		Connected bool   `json:"connected"`
		Ssid      string `json:"ssid"`
		IP        string `json:"ip"`
		Rssi      int    `json:"rssi"`
	} `json:"wifi_sta"`
	Cloud struct {
		Enabled   bool `json:"enabled"`
		Connected bool `json:"connected"`
	} `json:"cloud"`
	Mqtt struct {
		Connected bool `json:"connected"`
	} `json:"mqtt"`
	Time      string `json:"time"`
	Serial    int    `json:"serial"`
	HasUpdate bool   `json:"has_update"`
	Mac       string `json:"mac"`
	Lights    []struct {
		Ison       bool   `json:"ison"`
		Mode       string `json:"mode"`
		Brightness int    `json:"brightness"`
	} `json:"lights"`
	Meters []struct {
		Power     float64   `json:"power"`
		IsValid   bool      `json:"is_valid"`
		Timestamp int       `json:"timestamp"`
		Counters  []float64 `json:"counters"`
		Total     int       `json:"total"`
	} `json:"meters"`
	Inputs []struct {
		Input int `json:"input"`
	} `json:"inputs"`
	Tmp struct {
		TC      float64 `json:"tC"`
		TF      float64 `json:"tF"`
		IsValid string  `json:"is_valid"`
	} `json:"tmp"`
	CalibProgress   int  `json:"calib_progress"`
	Overtemperature bool `json:"overtemperature"`
	Loaderror       bool `json:"loaderror"`
	Overload        bool `json:"overload"`
	Update          struct {
		Status     string `json:"status"`
		HasUpdate  bool   `json:"has_update"`
		NewVersion string `json:"new_version"`
		OldVersion string `json:"old_version"`
	} `json:"update"`
	RAMTotal int `json:"ram_total"`
	RAMFree  int `json:"ram_free"`
	FsSize   int `json:"fs_size"`
	FsFree   int `json:"fs_free"`
	Uptime   int `json:"uptime"`
}

type DeviceSettings struct {
	Device struct {
		Type     string `json:"type"`
		Mac      string `json:"mac"`
		Hostname string `json:"hostname"`
	} `json:"device"`
	WifiAp struct {
		Enabled bool   `json:"enabled"`
		Ssid    string `json:"ssid"`
		Key     string `json:"key"`
	} `json:"wifi_ap"`
	WifiSta struct {
		Enabled    bool   `json:"enabled"`
		Ssid       string `json:"ssid"`
		Ipv4Method string `json:"ipv4_method"`
		IP         string `json:"ip"`
		Gw         string `json:"gw"`
		Mask       string `json:"mask"`
		DNS        string `json:"dns"`
	} `json:"wifi_sta"`
	WifiSta1 struct {
		Enabled    bool        `json:"enabled"`
		Ssid       interface{} `json:"ssid"`
		Ipv4Method string      `json:"ipv4_method"`
		IP         interface{} `json:"ip"`
		Gw         interface{} `json:"gw"`
		Mask       interface{} `json:"mask"`
		DNS        interface{} `json:"dns"`
	} `json:"wifi_sta1"`
	Mqtt struct {
		Enable              bool    `json:"enable"`
		Server              string  `json:"server"`
		User                string  `json:"user"`
		ReconnectTimeoutMax float64 `json:"reconnect_timeout_max"`
		ReconnectTimeoutMin float64 `json:"reconnect_timeout_min"`
		CleanSession        bool    `json:"clean_session"`
		KeepAlive           int     `json:"keep_alive"`
		WillTopic           string  `json:"will_topic"`
		WillMessage         string  `json:"will_message"`
		MaxQos              int     `json:"max_qos"`
		Retain              bool    `json:"retain"`
		UpdatePeriod        int     `json:"update_period"`
	} `json:"mqtt"`
	Sntp struct {
		Server string `json:"server"`
	} `json:"sntp"`
	Login struct {
		Enabled     bool   `json:"enabled"`
		Unprotected bool   `json:"unprotected"`
		Username    string `json:"username"`
		Password    string `json:"password"`
	} `json:"login"`
	PinCode            string `json:"pin_code"`
	CoiotExecuteEnable bool   `json:"coiot_execute_enable"`
	Name               string `json:"name"`
	Fw                 string `json:"fw"`
	BuildInfo          struct {
		BuildID        string    `json:"build_id"`
		BuildTimestamp time.Time `json:"build_timestamp"`
		BuildVersion   string    `json:"build_version"`
	} `json:"build_info"`
	Cloud struct {
		Enabled   bool `json:"enabled"`
		Connected bool `json:"connected"`
	} `json:"cloud"`
	Timezone      string        `json:"timezone"`
	Lat           float64       `json:"lat"`
	Lng           float64       `json:"lng"`
	Tzautodetect  bool          `json:"tzautodetect"`
	Time          string        `json:"time"`
	LightSensor   string        `json:"light_sensor"`
	Schedule      bool          `json:"schedule"`
	ScheduleRules []interface{} `json:"schedule_rules"`
	Sensors       struct {
		MotionDuration  int    `json:"motion_duration"`
		MotionLed       bool   `json:"motion_led"`
		TemperatureUnit string `json:"temperature_unit"`
	} `json:"sensors"`
}

var (
	service  = flag.String("service", "_http._tcp", "Set the service category to look for devices.")
	domain   = flag.String("domain", "local", "Set the search domain. For local networks, default is fine.")
	waitTime = flag.Int("wait", 90, "Duration in [s] to run discovery.")
	user     = flag.String("user", "admin", "Username for yor Shelly devices.")
	password = flag.String("password", "admin", "Password your the Shelly devices.")
)

func discoverShellys() {
	flag.Parse()
	log.Println("Shelly mDNS Discovery in progress..")
	// Discover all services on the network (e.g. _workstation._tcp)
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	entries := make(chan *zeroconf.ServiceEntry)
	fmt.Println("\"Hostname\";\"Url\";\"RSSI\";\"Temperature\";\"Network\";\"IP\";\"Subnet\";\"Gateway\"")
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {

			ipstring := entry.AddrIPv4[0].String()
			hostname := strings.Split(entry.HostName, ".")

			if strings.Contains(hostname[0], "shelly") {
				statusurl := "http://" + *user + ":" + *password + "@" + ipstring + "/status"
				settingsurl := "http://" + *user + ":" + *password + "@" + ipstring + "/settings"
				req, _ := http.NewRequest("GET", statusurl, nil)
				res, _ := http.DefaultClient.Do(req)

				reqset, _ := http.NewRequest("GET", settingsurl, nil)
				resset, _ := http.DefaultClient.Do(reqset)

				defer resset.Body.Close()
				defer res.Body.Close()
				body, _ := ioutil.ReadAll(res.Body)
				bodyset, _ := ioutil.ReadAll(resset.Body)

				//fmt.Println(string(bodyset))
				var devicestatus DeviceStatus
				json.Unmarshal(body, &devicestatus)
				var devicesettings DeviceSettings
				json.Unmarshal(bodyset, &devicesettings)

				rssi := strconv.Itoa(devicestatus.WifiSta.Rssi)
				nwtype := devicesettings.WifiSta.Ipv4Method
				gateway := devicesettings.WifiSta.Gw
				//ship := devicesettings.WifiSta.IP
				shsn := devicesettings.WifiSta.Mask

				temperature := fmt.Sprintf("%.2f", devicestatus.Tmp.TC)
				if temperature == "0.00" {
					temperature = ""
				}
				fmt.Println("\"" + hostname[0] + "\",\"http://" + ipstring + "\";\"" + rssi + "\";\"" + temperature + "\";\"" + nwtype + "\";\"\t" + ipstring + "\";\"" + shsn + "\";\"" + gateway + "\"")
			}
		}
		fmt.Println("")
		log.Println("mDNS Discovery finished.")
		os.Exit(0)

	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(*waitTime))
	defer cancel()
	err = resolver.Browse(ctx, *service, *domain, entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	<-ctx.Done()
	// Wait some additional time to see debug messages on go routine shutdown.
	time.Sleep(1 * time.Second)
}

func main() {
	discoverShellys()

	gocron.Every(5).Minutes().Do(discoverShellys)
	// Start all the pending jobs
	<-gocron.Start()
}
