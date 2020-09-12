package utilities

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
)

func request() ([]Bytes, error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(viper.GetString("cert"), viper.GetString("key"))
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(viper.GetString("ca"))
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Do GET something
	resp, err := client.Get(viper.GetString("authURL"))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	return data
}

