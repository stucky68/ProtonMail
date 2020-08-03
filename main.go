package main

import (
	"fmt"
)

func main()  {

	service := ProtonMailService{
		UserName: "6992917",
		PassWord: "QpfzEwZG3Lt6!$f",
	}


	fmt.Println(service.Login())
	service.GetUser()
	service.GetSalts()

	service.GetCookies()
	service.GetAddress()


	//fmt.Println(service.UserResult)
	//fmt.Println(service.AddressResult)

	msgResult, err := service.CreateDraft("我是标题", "6992917@qq.com", "", "")
	fmt.Println(msgResult.Message.ID, err)

	msgResult, err = service.CreateDraft("我是标题", "6992917@qq.com", msgResult.Message.ID, "<br><br><br>测试发送内容<br><br><br>")
	fmt.Println(msgResult.Message.ID, err)

	service.SendMessage(msgResult.Message.ID, msgResult.Message.Body)




	//salt, _ := base64.StdEncoding.DecodeString(service.SaltsResult.KeySalts[0].KeySalt)
	//generatedMailboxPassword, _ := srp.MailboxPassword(service.PassWord, salt)
	//generatedMailboxPassword = strings.ReplaceAll(generatedMailboxPassword, "$2y$10$", "")
	//generatedMailboxPassword = strings.ReplaceAll(generatedMailboxPassword, string(Radix64Encode(salt)), "")
	//
	//fmt.Println(generatedMailboxPassword)
	//
	//pgpMessage, _:= crypto.NewPGPSplitMessageFromArmored(msgResult.Message.Body)
	//
	//fmt.Println(pgpMessage.DataPacket)
	//fmt.Println(pgpMessage.KeyPacket)
	//
	//privaetKey, _ := crypto.NewKeyFromArmored(service.AddressResult.Addresses[0].Keys[0].PrivateKey)
	//key, _ := privaetKey.Unlock([]byte(generatedMailboxPassword))
	//
	//keyRing, _ := crypto.NewKeyRing(key)
	//SessionKey, _ := keyRing.DecryptSessionKey(pgpMessage.KeyPacket)
	//fmt.Println(base64.StdEncoding.EncodeToString(SessionKey.Key))
	//
	//fmt.Println(base64.StdEncoding.EncodeToString(pgpMessage.DataPacket))


}
