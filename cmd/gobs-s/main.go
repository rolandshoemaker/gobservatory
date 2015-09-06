package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/rolandshoemaker/gobservatory/api/submission"
	"github.com/rolandshoemaker/gobservatory/db"

	"github.com/rolandshoemaker/gobservatory/core"
	"github.com/rolandshoemaker/gobservatory/external/asnFinder"
)

type config struct {
	SubmissionAPI struct {
		core.ServerConfig `yaml:",inline"`

		CertPath string `yaml:"certPath"`
		KeyPath  string `yaml:"keyPath"`
	} `yaml:"submissionAPI"`
	WHOIS struct {
		core.ServerConfig `yaml:",inline"`

		Timeout   string `yaml:"timeout"`
		KeepAlive string `yaml:"keepAlive"`
	} `yaml:"whois"`
	StatsD struct {
		core.ServerConfig `yaml:",inline"`
	} `yaml:"statsd"`
	DbURI string `yaml:"dbURI"`
}

func main() {
	configFilename := "config.yml"
	content, err := ioutil.ReadFile(configFilename)
	if err != nil {
		fmt.Println(err)
		return
	}
	var c config
	err = yaml.Unmarshal(content, &c)
	whoisTimeout, err := time.ParseDuration(c.WHOIS.Timeout)
	if err != nil {
		fmt.Println(err)
		return
	}
	whoisKeepAlive, err := time.ParseDuration(c.WHOIS.KeepAlive)
	if err != nil {
		fmt.Println(err)
		return
	}
	asnFinder := asnFinder.New(c.WHOIS.Host, c.WHOIS.Port, whoisTimeout, whoisKeepAlive)
	database := db.New()

	nssPool, err := core.PoolFromPEM("roots/nss_list.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	obs := submission.New(nssPool, nil, c.SubmissionAPI.Host, c.SubmissionAPI.Port, asnFinder, database)
	go func() {
		obs.ParseSubmissions()
	}()
	err = obs.Serve()
	if err != nil {
		fmt.Println(err)
		return
	}
}
