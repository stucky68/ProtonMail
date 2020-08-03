package main

import (
	"encoding/base64"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func main()  {


	//service := ProtonMailService{
	//	UserName: "6992917",
	//	PassWord: "QpfzEwZG3Lt6!$f",
	//}
	//
	//fmt.Println(service.Login())
	//
	//service.GetUser()
	//service.GetCookies()
	//service.GetAddress()
	//
	////fmt.Println(service.UserResult)
	////fmt.Println(service.AddressResult)
	//
	//msgResult, err := service.CreateDraft("ttt", "6992917@qq.com", "", "")
	//fmt.Println(msgResult.Message.ID, err)
	//
	//msgResult, err = service.CreateDraft("ttt", "6992917@qq.com", msgResult.Message.ID, "发送内容")
	//fmt.Println(msgResult.Message.ID, err)



	//publicKeyObj, err := crypto.NewKeyFromArmored(service.AddressResult.Addresses[0].Keys[0].PublicKey)
	//publicKeyRing, err := crypto.NewKeyRing(publicKeyObj)
	//
	sessionKey, _ := crypto.GenerateSessionKey()
	//
	//keyPacket, err := publicKeyRing.EncryptSessionKey(sessionKey) // Will encrypt to all the keys in the keyring


	var message = crypto.NewPlainMessage([]byte("t"))

	fmt.Println(base64.StdEncoding.EncodeToString(sessionKey.Key))
	// Encrypt data with session key
	dataPacket, _ := sessionKey.Encrypt(message)
	//fmt.Println(base64.StdEncoding.EncodeToString(dataPacket), err)

	pgpSplitMessage := crypto.NewPGPSplitMessage(sessionKey.Key, dataPacket)
	pgpMessage := pgpSplitMessage.GetPGPMessage()

	fmt.Println(base64.StdEncoding.EncodeToString(pgpMessage.Data))

	newPGPSplitMessage, _ := pgpMessage.SeparateKeyAndData(len(pgpMessage.Data), 1)
	fmt.Println(newPGPSplitMessage)

	fmt.Println(base64.StdEncoding.EncodeToString(newPGPSplitMessage.DataPacket), base64.StdEncoding.EncodeToString(newPGPSplitMessage.KeyPacket))
}
