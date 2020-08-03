package main

import (
	"ProtonMail/srp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"io/ioutil"
	"net/http"
	"strings"
)

type ProtonMailService struct {
	UserName string
	PassWord string

	UserResult UserResult
	SaltsResult SaltsResult
	AuthResult AuthResult
	AddressResult AddressResult

	CookiesRaw string

	passphrase string
}

func (service *ProtonMailService) Info() (result GetInfoResult, err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Content-Type"] = "application/json"

	body, err := HttpPost("https://mail.protonmail.com/api/auth/info", header, "{\"Username\":\"" + service.UserName + "\"}")

	if err != nil {
		return
	}

	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return
	}

	if result.Code != 1000 {
		return result, errors.New(result.Error)
	}
	return
}

func (service *ProtonMailService) auth(ClientEphemeral, ClientProof, SRPSession string) (result AuthResult, err error) {
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

	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Content-Type"] = "application/json"
	body, err := HttpPost("https://mail.protonmail.com/api/auth", header, string(d))

	if err != nil {
		return
	}

	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return
	}

	if result.Code != 1000 {
		return result, errors.New(result.Error)
	}
	return
}

func (service *ProtonMailService) GetUser() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = service.AuthResult.Uid
	header["Authorization"] = "Bearer " + service.AuthResult.AccessToken

	body, err := HttpGet("https://mail.protonmail.com/api/users", header)
	err = json.Unmarshal([]byte(body), &service.UserResult)

	if err != nil {
		return
	}

	if service.UserResult.Code != 1000 {
		err = errors.New(service.UserResult.Error)
	}

	return
}

func (service *ProtonMailService) GetSalts() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = service.AuthResult.Uid
	header["Authorization"] = "Bearer " + service.AuthResult.AccessToken

	body, err := HttpGet("https://mail.protonmail.com/api/keys/salts", header)

	if err != nil {
		return
	}

	err = json.Unmarshal([]byte(body), &service.SaltsResult)

	if err != nil {
		return
	}

	if service.SaltsResult.Code == 1000 {
		salt, err := base64.StdEncoding.DecodeString(service.SaltsResult.KeySalts[0].KeySalt)
		if err != nil {
			return err
		}

		generatedMailboxPassword, err := srp.MailboxPassword(service.PassWord, salt)
		if err != nil {
			return err
		}

		generatedMailboxPassword = strings.ReplaceAll(generatedMailboxPassword, "$2y$10$", "")
		generatedMailboxPassword = strings.ReplaceAll(generatedMailboxPassword, string(Radix64Encode(salt)), "")

		service.passphrase = generatedMailboxPassword
	} else {
		err = errors.New(service.SaltsResult.Error)
	}

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

func (service *ProtonMailService) GetAddress() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = service.AuthResult.Uid
	header["Cookie"] = service.CookiesRaw

	body, err := HttpGet("https://mail.protonmail.com/api/addresses", header)
	err = json.Unmarshal([]byte(body), &service.AddressResult)
	if err != nil {
		return
	}

	if service.AddressResult.Code != 1000 {
		err = errors.New(service.AddressResult.Error)
	}

	return
}

func (service *ProtonMailService) SendMessage(msgId, msgBody, receiver string) (err error) {
	pgpMessage, err := crypto.NewPGPSplitMessageFromArmored(msgBody)
	if err != nil {
		return
	}

	privaetKey, err := crypto.NewKeyFromArmored(service.AddressResult.Addresses[0].Keys[0].PrivateKey)
	if err != nil {
		return
	}

	key, err := privaetKey.Unlock([]byte(service.passphrase))
	if err != nil {
		return
	}

	keyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return
	}

	SessionKey, err := keyRing.DecryptSessionKey(pgpMessage.KeyPacket)
	if err != nil {
		return
	}

	var packages []SendMeesagePackages

	addresses := make(map[string]SendMessageAddresses)
	addresses[receiver] = SendMessageAddresses{
		Type:      4,
		Signature: 0,
	}
	
	pkg := SendMeesagePackages{
		Flags:          1,
		Addresses:      addresses,
		MIMEType:       "text/html",
		Body:           base64.StdEncoding.EncodeToString(pgpMessage.DataPacket),
		Type:           4,
		AttachmentKeys: struct{}{},
		BodyKey: struct {
			Key       string `json:"Key"`
			Algorithm string `json:"Algorithm"`
		}{
			base64.StdEncoding.EncodeToString(SessionKey.Key),
			SessionKey.Algo,
		},
	}

	packages = append(packages, pkg)

	sendMessageData := SendMessageData{
		Id:       msgId,
		Packages: packages,
	}

	d, err := json.Marshal(&sendMessageData)
	if err != nil {
		return
	}


	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = service.AuthResult.Uid
	header["Cookie"] = service.CookiesRaw

	body, err := HttpPost("https://mail.protonmail.com/api/messages/" + msgId, header, string(d))

	fmt.Println(body)

	return
}

func (service *ProtonMailService) CreateDraft(title, receiver, id, plaintext string) (result MessageResult, err error) {

	armor, err := helper.EncryptSignMessageArmored(service.AddressResult.Addresses[0].Keys[0].PublicKey, service.AddressResult.Addresses[0].Keys[0].PrivateKey, []byte(service.passphrase), plaintext)
	if err != nil {
		return
	}

	var toList []ToList
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

	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = service.AuthResult.Uid
	header["Cookie"] = service.CookiesRaw

	body := ""
	if id != "" {
		body, err = HttpPut("https://mail.protonmail.com/api/messages/" + id, header, string(d))
	} else {
		body, err = HttpPost("https://mail.protonmail.com/api/messages", header, string(d))
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return
	}

	if result.Code != 1000 {
		err = errors.New(result.Error)
	}

	return
}

func (service *ProtonMailService) Login() (err error) {
	infoResult, err := service.Info()
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

	err = service.GetUser()
	if err != nil {
		return
	}
	err = service.GetSalts()
	if err != nil {
		return
	}

	err = service.GetCookies()
	if err != nil {
		return
	}

	err = service.GetAddress()
	if err != nil {
		return
	}

	return
}
