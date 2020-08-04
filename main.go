package main

import (
	"ProtonMail/Logging"
	"ProtonMail/model"
	"ProtonMail/service"
	"ProtonMail/task"
	"ProtonMail/utils"
	"encoding/json"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"io/ioutil"
	"strings"
	"sync"
)

type Para struct {
	Task *task.Task
	Receiver string
	Title string
	PlainText string
}

func main()  {
	var clients []*service.ProtonMailClient

	//读取发件小号
	str := utils.ReadFile("./sender.txt")
	lines := strings.Split(str, "\r\n")
	for _, line := range lines {
		v := strings.Split(line,"----")
		if len(v) == 2{
			client := service.NewProtonMailClient(v[0], v[1])
			clients = append(clients, client)
		}
	}

	//读取收件箱
	var receivers []string
	str = utils.ReadFile("./receiver.txt")
	lines = strings.Split(str, "\r\n")
	for _, line := range lines {
		receivers = append(receivers, line)
	}

	fmt.Println(receivers)

	//读取配置文件
	config := &model.SendConfig{}
	str = utils.ReadFile("./config.json")
	err := json.Unmarshal([]byte(str), config)
	if err != nil {
		panic(err)
	}

	var tasks []*task.Task
	for _, c := range clients {
		task := task.NewTask(c, config.WaitTime, config.SendCount, config.Value)
		tasks = append(tasks, task)
	}

	wg := sync.WaitGroup{}
	pool, err := ants.NewPoolWithFunc(config.ThreadNum, func(i interface{}) {
		p := i.(*Para)
		p.Task.Process(p.Receiver, p.Title, p.PlainText)
		wg.Done()
	})

	if err != nil {
		panic(err)
	}

	defer pool.Release()

	for i, recv := range receivers {
		wg.Add(1)
		p := &Para{
			Task:      tasks[i % len(tasks)],
			Receiver:  recv,
			Title:     config.Title,
			PlainText: config.Content,
		}
		err := pool.Invoke(p)
		if err != nil {
			panic(err)
		}
	}

	wg.Wait()

	Logging.Println("工作完毕")

	success := 0
	failed := 0

	var notSend []string

	for _, task := range tasks {
		success += task.GetSuccess()
		failed += task.GetFailed()

		for _, v := range task.GetNotSend() {
			notSend = append(notSend, v)
		}
	}

	str = fmt.Sprintf("发送成功统计:%d 发送失败统计%d", success, failed)
	Logging.Println(str)

	saveText := ""
	for _, v := range notSend {
		saveText += v
		saveText += "\r\n"
	}
	ioutil.WriteFile("未发送.txt", []byte(saveText), 06666)
}
