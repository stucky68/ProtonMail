package utils

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func HttpPostCookies(url string, methond string, header map[string]string, data string) (string, []*http.Cookie, error) {
	client := &http.Client{}

	payload := strings.NewReader(data)

	req, err := http.NewRequest(methond, url, payload)
	if err != nil {
		return "", nil, err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	defer res.Body.Close()
	if err != nil {
		return "", nil, err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", nil, err
	}
	return string(b), res.Cookies(), nil
}

func HttpPost(url string, methond string, header map[string]string, data string) (string, error) {
	client := &http.Client{}

	payload := strings.NewReader(data)

	req, err := http.NewRequest(methond, url, payload)
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