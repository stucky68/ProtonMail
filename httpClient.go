package main

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func HttpPut(url string, header map[string]string, data string) (string, error) {
	client := &http.Client{}

	payload := strings.NewReader(data)

	req, err := http.NewRequest("PUT", url, payload)
	if err != nil {
		return "", err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	defer res.Body.Close()
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func HttpPost(url string, header map[string]string, data string) (string, error) {
	client := &http.Client{}

	payload := strings.NewReader(data)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return "", err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	defer res.Body.Close()
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func HttpGet(url string, header map[string]string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}