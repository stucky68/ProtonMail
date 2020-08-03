package main

import (
	"ProtonMail/srp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"io/ioutil"
	"net/http"
	"strings"
)

type ProtonMailService struct {
	UserName string
	PassWord string

	UserResult UserResult
	AuthResult AuthResult
	AddressResult AddressResult

	CookiesRaw string
}

func (service *ProtonMailService) info(userName string) (result GetInfoResult, err error) {
	url := "https://mail.protonmail.com/api/auth/info"
	method := "POST"

	payload := strings.NewReader("{\"Username\":\"" + service.UserName + "\"}")

	client := &http.Client {}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return
	}
	req.Header.Add("x-pm-apiversion", "3")
	req.Header.Add("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Add("x-pm-appversion", "Web_3.16.32")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &result)
	return
}

func (service *ProtonMailService) auth(ClientEphemeral, ClientProof, SRPSession string) (result AuthResult, err error) {
	url := "https://mail.protonmail.com/api/auth"
	method := "POST"

	authData := AuthData{
		ClientEphemeral: ClientEphemeral,
		ClientProof:     ClientProof,
		SRPSession:      SRPSession,
		Username:        service.UserName,
	}

	d, err := json.Marshal(&authData)
	if err != nil {
		return
	}

	payload := strings.NewReader(string(d))

	client := &http.Client {}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return
	}
	req.Header.Add("x-pm-apiversion", "3")
	req.Header.Add("x-pm-appversion", "Web_3.16.32")
	req.Header.Add("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &result)
	return
}

func (service *ProtonMailService) GetUser() {
	url := "https://mail.protonmail.com/api/users"
	method := "GET"

	client := &http.Client {}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		return
	}
	req.Header.Add("x-pm-apiversion", "3")
	req.Header.Add("x-pm-appversion", "Web_3.16.32")
	req.Header.Add("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-pm-uid", service.AuthResult.Uid)
	req.Header.Add("Authorization", "Bearer " + service.AuthResult.AccessToken)

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &service.UserResult)
	return
}

func (service *ProtonMailService) GetCookies() (err error) {
	url := "https://mail.protonmail.com/api/auth/cookies"
	method := "POST"

	cookiesData := CookiesData{
		AccessToken:  service.AuthResult.AccessToken,
		GrantType:    "refresh_token",
		RedirectURI:  "https://protonmail.com",
		RefreshToken: service.AuthResult.RefreshToken,
		ResponseType: "token",
		State:        GetRandomString(24),
		UID:          service.AuthResult.Uid,
	}

	d, err := json.Marshal(&cookiesData)
	if err != nil {
		return
	}

	payload := strings.NewReader(string(d))

	client := &http.Client {}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return
	}
	req.Header.Add("x-pm-apiversion", "3")
	req.Header.Add("x-pm-appversion", "Web_3.16.32")
	req.Header.Add("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-pm-uid", service.AuthResult.Uid)
	req.Header.Add("Authorization", "Bearer " + service.AuthResult.AccessToken)

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if len(res.Cookies()) > 2 {
		service.CookiesRaw = res.Cookies()[1].Raw
	} else {
		err = errors.New("cookies error")
	}

	return
}

func (service *ProtonMailService) GetAddress() {
	url := "https://mail.protonmail.com/api/addresses"
	method := "GET"

	client := &http.Client {}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		return
	}
	req.Header.Add("x-pm-apiversion", "3")
	req.Header.Add("x-pm-appversion", "Web_3.16.32")
	req.Header.Add("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-pm-uid", service.AuthResult.Uid)
	req.Header.Add("Cookie", service.CookiesRaw)

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &service.AddressResult)
	return
}

func (service *ProtonMailService) CreateDraft(title, receiver, id, plaintext string) (result MessageResult, err error) {
	url := "https://mail.protonmail.com/api/messages"
	method := "POST"
	if id != "" {
		url = "https://mail.protonmail.com/api/messages/" + id
		method = "PUT"
	}

	armor, err := helper.EncryptMessageArmored(service.AddressResult.Addresses[0].Keys[0].PublicKey, plaintext)

	toList := []ToList{}
	toList = append(toList, ToList{
		Address:        receiver,
		Name:           receiver,
		Encrypt:        false,
		Invalid:        false,
		IsContactGroup: false,
		IsEO:           false,
		IsPgp:          false,
		IsPgpMime:      false,
		IsPinned:       false,
		Label:          receiver,
		LoadCryptInfo:  false,
		Sign:           false,
		Warnings:       nil,
	})

	msg := Message{
		ToList:   toList,
		CCList:   []string{},
		BCCList:  []string{},
		Subject:  title,
		Unread:   0,
		MIMEType: "text/html",
		Flags:    0,
		Sender: struct {
			Name    string `json:"Name"`
			Address string `json:"Address"`
		}{
			service.AddressResult.Addresses[0].DisplayName,
			service.AddressResult.Addresses[0].Email,
		},
		AddressID:            service.AddressResult.Addresses[0].ID,
		Body:                 armor,
		Id:                   id,
		AttachmentKeyPackets: struct{}{},
	}

	messageData := MessageData{Message:msg}

	d, err := json.Marshal(&messageData)
	if err != nil {
		return
	}

	payload := strings.NewReader(string(d))

	client := &http.Client {}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return
	}
	req.Header.Add("x-pm-apiversion", "3")
	req.Header.Add("x-pm-appversion", "Web_3.16.32")
	req.Header.Add("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-pm-uid", service.AuthResult.Uid)
	req.Header.Add("Cookie", service.CookiesRaw)

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	fmt.Println(string(body))

	err = json.Unmarshal(body, &result)
	return
}

func (service *ProtonMailService) Login() (err error) {
	infoResult, err := service.info(service.UserName)
	if err != nil {
		return
	}

	auth, err := srp.NewAuth(infoResult.Version, service.UserName, service.PassWord, infoResult.Salt, infoResult.Modulus, infoResult.ServerEphemeral)
	if err != nil {
		return
	}

	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return
	}

	service.AuthResult, err = service.auth(base64.StdEncoding.EncodeToString(proofs.ClientEphemeral), base64.StdEncoding.EncodeToString(proofs.ClientProof), infoResult.SRPSession)
	return err
}
