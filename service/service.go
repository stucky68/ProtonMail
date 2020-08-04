package service

import (
	"ProtonMail/model"
	"ProtonMail/srp"
	"ProtonMail/utils"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"strings"
)

type ProtonMailClient struct {
	userName string
	passWord string

	authResult model.AuthResult

	publicKey   string
	privateKey  string
	displayName string
	email       string
	addressID   string

	cookiesRaw string

	passphrase string

	isLogin bool
}

func NewProtonMailClient(userName, passWord string) *ProtonMailClient {
	client := ProtonMailClient{
		userName: userName,
		passWord: passWord,
		isLogin:  false,
	}
	return &client
}

func (client *ProtonMailClient) GetUserName() string {
	return client.userName
}

func (client *ProtonMailClient) Info() (result model.GetInfoResult, err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Content-Type"] = "application/json"

	body, err := utils.HttpPost("https://mail.protonmail.com/api/auth/info", "POST", header, "{\"Username\":\"" + client.userName+ "\"}")

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

func (client *ProtonMailClient) auth(ClientEphemeral, ClientProof, SRPSession string) (result model.AuthResult, err error) {
	authData := model.AuthData{
		ClientEphemeral: ClientEphemeral,
		ClientProof:     ClientProof,
		SRPSession:      SRPSession,
		Username:        client.userName,
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
	body, err := utils.HttpPost("https://mail.protonmail.com/api/auth", "POST", header, string(d))

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

func (client *ProtonMailClient) GetUser() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = client.authResult.Uid
	header["Authorization"] = "Bearer " + client.authResult.AccessToken

	body, err := utils.HttpGet("https://mail.protonmail.com/api/users", header)

	result := model.UserResult{}

	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return
	}

	if result.Code != 1000 {
		err = errors.New(result.Error)
	}

	return
}

func (client *ProtonMailClient) GetSalts() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = client.authResult.Uid
	header["Authorization"] = "Bearer " + client.authResult.AccessToken

	body, err := utils.HttpGet("https://mail.protonmail.com/api/keys/salts", header)

	if err != nil {
		return
	}

	saltsResult := model.SaltsResult{}
	err = json.Unmarshal([]byte(body), &saltsResult)

	if err != nil {
		return
	}

	if saltsResult.Code == 1000 {
		//Logging.Println(saltsResult)
		if len(saltsResult.KeySalts) > 0 {
			salt, err := base64.StdEncoding.DecodeString(saltsResult.KeySalts[0].KeySalt)
			if err != nil {
				return err
			}

			generatedMailboxPassword, err := srp.MailboxPassword(client.passWord, salt)
			if err != nil {
				return err
			}

			generatedMailboxPassword = strings.ReplaceAll(generatedMailboxPassword, "$2y$10$", "")
			generatedMailboxPassword = strings.ReplaceAll(generatedMailboxPassword, string(utils.Radix64Encode(salt)), "")

			client.passphrase = generatedMailboxPassword
		} else {
			return errors.New("KeySalts Not Found")
		}
	} else {
		err = errors.New(saltsResult.Error)
	}

	return
}

func (client *ProtonMailClient) GetCookies() (err error) {
	cookiesData := model.CookiesData{
		AccessToken:  client.authResult.AccessToken,
		GrantType:    "refresh_token",
		RedirectURI:  "https://protonmail.com",
		RefreshToken: client.authResult.RefreshToken,
		ResponseType: "token",
		State:        utils.GetRandomString(24),
		UID:          client.authResult.Uid,
	}

	d, err := json.Marshal(&cookiesData)
	if err != nil {
		return
	}

	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = client.authResult.Uid
	header["Authorization"] = "Bearer " + client.authResult.AccessToken

	body, cookies, err := utils.HttpPostCookies("https://mail.protonmail.com/api/auth/cookies", "POST", header, string(d))
	if err != nil {
		return
	}

	result := model.CookiesResult{}
	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return
	}

	if result.Code != 1000 {
		err = errors.New(result.Error)
	}

	for _, v := range cookies {
		index := strings.Index(v.Raw, "AUTH")
		if index != -1 {
			client.cookiesRaw = v.Raw
		}
	}

	if client.cookiesRaw == "" {
		err = errors.New("cookies error")
	}

	return
}

func (client *ProtonMailClient) GetAddress() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = client.authResult.Uid
	header["Cookie"] = client.cookiesRaw

	body, err := utils.HttpGet("https://mail.protonmail.com/api/addresses", header)

	addressResult := model.AddressResult{}

	err = json.Unmarshal([]byte(body), &addressResult)
	if err != nil {
		return
	}

	if addressResult.Code != 1000 {
		err = errors.New(addressResult.Error)
	} else {
		if len(addressResult.Addresses) == 0 {
			err = errors.New("addresses not found")
		} else if len(addressResult.Addresses[0].Keys) == 0 {
			err = errors.New("key not found")
		} else {
			client.publicKey = addressResult.Addresses[0].Keys[0].PublicKey
			client.privateKey = addressResult.Addresses[0].Keys[0].PrivateKey
			client.displayName = addressResult.Addresses[0].DisplayName
			client.email = addressResult.Addresses[0].Email
			client.addressID = addressResult.Addresses[0].ID
		}
	}

	return
}

func (client *ProtonMailClient) SendMessage(msgId, msgBody, receiver string) (err error) {
	pgpMessage, err := crypto.NewPGPSplitMessageFromArmored(msgBody)
	if err != nil {
		return
	}

	privaetKey, err := crypto.NewKeyFromArmored(client.privateKey)
	if err != nil {
		return
	}

	key, err := privaetKey.Unlock([]byte(client.passphrase))
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

	var packages []model.SendMeesagePackages

	addresses := make(map[string]model.SendMessageAddresses)
	addresses[receiver] = model.SendMessageAddresses{
		Type:      4,
		Signature: 0,
	}
	
	pkg := model.SendMeesagePackages{
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

	sendMessageData := model.SendMessageData{
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
	header["x-pm-uid"] = client.authResult.Uid
	header["Cookie"] = client.cookiesRaw

	body, err := utils.HttpPost("https://mail.protonmail.com/api/messages/" + msgId, "POST", header, string(d))
	if err != nil {
		return
	}

	result := model.MessageResult{}
	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return
	}

	if result.Code != 1000 {
		err = errors.New(result.Error)
	}
	return
}

func (client *ProtonMailClient) CreateDraft(title, receiver, id, plaintext string) (result model.MessageResult, err error) {
	armor, err := helper.EncryptSignMessageArmored(client.publicKey, client.privateKey, []byte(client.passphrase), plaintext)
	if err != nil {
		return
	}

	var toList []model.ToList
	toList = append(toList, model.ToList{
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

	msg := model.Message{
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
			client.displayName,
			client.email,
		},
		AddressID:            client.addressID,
		Body:                 armor,
		Id:                   id,
		AttachmentKeyPackets: struct{}{},
	}

	messageData := model.MessageData{Message: msg}

	d, err := json.Marshal(&messageData)
	if err != nil {
		return
	}

	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = client.authResult.Uid
	header["Cookie"] = client.cookiesRaw

	body := ""
	if id != "" {
		body, err = utils.HttpPost("https://mail.protonmail.com/api/messages/" + id, "PUT", header, string(d))
	} else {
		body, err = utils.HttpPost("https://mail.protonmail.com/api/messages", "POST", header, string(d))
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

func (client *ProtonMailClient) Logout() (err error) {
	header := make(map[string]string)
	header["x-pm-apiversion"] = "3"
	header["x-pm-appversion"] = "Web_3.16.32"
	header["Accept"] = "application/vnd.protonmail.v1+json"
	header["Content-Type"] = "application/json"
	header["x-pm-uid"] = client.authResult.Uid
	header["Cookie"] = client.cookiesRaw

	body, err := utils.HttpPost("https://mail.protonmail.com/api/auth", "DELETE", header, "")

	if err != nil {
		return
	}

	result := client.authResult

	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return
	}

	if result.Code != 1000 {
		return errors.New(result.Error)
	}

	return
}

func (client *ProtonMailClient) IsLogin() bool {
	return client.isLogin
}

func (client *ProtonMailClient) Login() (err error) {
	if client.isLogin {
		return
	}

	infoResult, err := client.Info()
	if err != nil {
		return errors.New(" Info " + err.Error())
	}

	auth, err := srp.NewAuth(infoResult.Version, client.userName, client.passWord, infoResult.Salt, infoResult.Modulus, infoResult.ServerEphemeral)
	if err != nil {
		return errors.New(" NewAuth " + err.Error())
	}

	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return errors.New(" GenerateProofs " + err.Error())
	}

	client.authResult, err = client.auth(base64.StdEncoding.EncodeToString(proofs.ClientEphemeral), base64.StdEncoding.EncodeToString(proofs.ClientProof), infoResult.SRPSession)
	if err != nil {
		return errors.New(" Auth " + err.Error())
	}

	err = client.GetUser()
	if err != nil {
		return errors.New(" GetUser " + err.Error())
	}
	err = client.GetSalts()
	if err != nil {
		return errors.New(" GetSalts " + err.Error())
	}

	err = client.GetCookies()
	if err != nil {
		return errors.New(" GetCookies " + err.Error())
	}

	err = client.GetAddress()
	if err != nil {
		return errors.New(" GetAddress " + err.Error())
	}

	client.isLogin = true
	return
}
