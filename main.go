package main

import (
	 "ProtonMail/service"
	"fmt"
)

func main()  {

	client := service.NewProtonMailClient("6992917","QpfzEwZG3Lt6!$f")

	fmt.Println(client.Login())

	receiver := "6992917@qq.com"

	//fmt.Println(service.UserResult)
	//fmt.Println(service.AddressResult)

	msgResult, err := client.CreateDraft("测试一下发送标题", receiver, "", "<br><br><br>发送内容是这样的<br><br><br>")
	fmt.Println(msgResult.Message.ID, err)

	//msgResult, err = client.CreateDraft("我是标题", receiver, msgResult.Message.ID, "")
	//fmt.Println(msgResult.Message.ID, err)

	err = client.SendMessage(msgResult.Message.ID, msgResult.Message.Body, receiver)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("发送邮件成功")
	}

	fmt.Println(client.Logout())
}
