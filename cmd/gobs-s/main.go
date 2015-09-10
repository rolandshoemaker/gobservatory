package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/rolandshoemaker/gobservatory/Godeps/_workspace/src/gopkg.in/yaml.v2"

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
	DbURI     string `yaml:"dbURI"`
	Workers   int    `yaml:"submissionWorkers"`
	NSSPool   string `yaml:"nssPoolPEM"`
	MSPool    string `yaml:"msPoolPEM"`
	TransPool string `yaml:"transPoolPEM"`
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
	asnFinder := asnFinder.New(
		c.WHOIS.Host,
		c.WHOIS.Port,
		whoisTimeout,
		whoisKeepAlive,
	)
	database, err := db.New()
	if err != nil {
		fmt.Println(err)
		return
	}

	nssPool, err := core.PoolFromPEM(c.NSSPool)
	if err != nil {
		fmt.Println(err)
		return
	}
	msPool, err := core.PoolFromPEM(c.MSPool)
	if err != nil {
		fmt.Println(err)
		return
	}
	transPool, err := core.PoolFromPEM(c.TransPool)
	if err != nil {
		fmt.Println(err)
		return
	}
	stats, err := statsd.NewClient(net.JoinHostPort(c.StatsD.Host, c.StatsD.Port), "gobservatory")
	if err != nil {
		fmt.Println(err)
		return
	}
	go core.ProfileCmd(stats)
	obs := submission.New(
		nssPool,
		msPool,
		transPool,
		c.SubmissionAPI.Host,
		c.SubmissionAPI.Port,
		asnFinder,
		database,
		stats,
	)

	wg := new(sync.WaitGroup)
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		go obs.ParseSubmissions(wg)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		for _ = range sigChan {
			fmt.Println("\nInterrupt! Shutting down API server and waiting for remaining submissions to be processed")
			err = obs.Shutdown()
			if err != nil {
				fmt.Printf("Problem shutting down API server: %s\n", err)
				return
			}
		}
	}()

	err = obs.Serve("", "")
	if err != nil {
		fmt.Println(err)
		return
	}
	wg.Wait()
}
