package task

import (
	"ProtonMail/Logging"
	"ProtonMail/model"
	"ProtonMail/service"
	"ProtonMail/utils"
	"fmt"
	"strings"
	"time"
)

type Task struct {
	client *service.ProtonMailClient

	success int
	failed int
	sendCount int
	waitTime int

	notSend []string

	valueConfig model.ValueConfig
}

const (
	RandUpper = 1
	RandLetter = 2
	RandHan = 3
	RandNum = 4
	RandCustom = 5
)

func NewTask(client *service.ProtonMailClient, waitTime, sendCount int, valueConfig model.ValueConfig) *Task {
	task := Task{
		client:      client,
		success:     0,
		failed:      0,
		sendCount:   sendCount,
		waitTime:    waitTime,
		valueConfig: valueConfig,
	}
	return &task
}

func (task *Task) GetFailed() int {
	return task.failed
}

func (task *Task) GetSuccess() int{
	return task.success
}

func (task *Task) GetNotSend() []string {
	return task.notSend
}

func (task *Task) Process(receiver string, title string, plainText string) {
	f := func() {
		task.failed++
		task.notSend = append(task.notSend, receiver)
	}

	if task.failed + task.success > task.sendCount {
		f()
		return
	}

	defer time.Sleep(time.Second * time.Duration(task.waitTime))

	if !task.client.IsLogin() {
		str := fmt.Sprintf("%s正在登陆", task.client.GetUserName())
		Logging.Println(str)
	}

	err := task.client.Login()
	if err != nil {
		str := fmt.Sprintf("%s出现错误%s", task.client.GetUserName(), err.Error())
		Logging.Println(str)
		f()
		return
	}

	text := plainText
	switch task.valueConfig.ValueType {
	case RandUpper:
		text = utils.RandUpper(task.valueConfig.ValueLength) + text + utils.RandUpper(task.valueConfig.ValueLength)
	case RandLetter:
		text = utils.RandLetter(task.valueConfig.ValueLength) + text + utils.RandLetter(task.valueConfig.ValueLength)
	case RandHan:
		text = utils.RandHan(task.valueConfig.ValueLength) + text + utils.RandHan(task.valueConfig.ValueLength)
	case RandNum:
		text = utils.RandNum(task.valueConfig.ValueLength) + text + utils.RandNum(task.valueConfig.ValueLength)
	case RandCustom:
		v := strings.Split(task.valueConfig.CustomValue, "|")
		left := ""
		right := ""
		if len(v) > 0 {
			left = v[utils.RandInt(0, int64(len(v)-1))]
			right = v[utils.RandInt(0, int64(len(v)-1))]
		}
		text = left + text + right
	}

	msgResult, err := task.client.CreateDraft(title, receiver, "", text)
	if err != nil {
		str := fmt.Sprintf("%s CreateDraft 出现错误%s", task.client.GetUserName(), err.Error())
		Logging.Println(str)
		f()
		return
	}

	err = task.client.SendMessage(msgResult.Message.ID, msgResult.Message.Body, receiver)
	if err != nil {
		str := fmt.Sprintf("%s SendMessage 出现错误%s", task.client.GetUserName(), err.Error())
		Logging.Println(str)
		f()
	} else {
		str := fmt.Sprintf("%s发送邮件至%s成功", task.client.GetUserName(), receiver)
		Logging.Println(str)
		task.success++
	}
}