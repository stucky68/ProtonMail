package main

type ToList struct {
	Address string `json:"Address"`
	Name string `json:"Name"`
	Encrypt bool `json:"encrypt"`
	Invalid bool `json:"invalid"`
	IsContactGroup bool `json:"isContactGroup"`
	IsEO bool `json:"isEO"`
	IsPgp bool `json:"isPgp"`
	IsPgpMime bool `json:"isPgpMime"`
	IsPinned bool `json:"isPinned"`
	Label string `json:"label"`
	LoadCryptInfo bool `json:"loadCryptInfo"`
	Sign bool `json:"sign"`
	Warnings []string `json:"warnings"`
}

type Message struct {
	ToList[] ToList `json:"ToList"`
	CCList[] string `json:"CCList"`
	BCCList[] string `json:"BCCList"`
	Subject string `json:"Subject"`
	Unread int `json:"Unread"`
	MIMEType string `json:"MIMEType"`
	Flags int `json:"Flags"`
	Sender struct {
		Name string `json:"Name"`
		Address string `json:"Address"`
	}
	AddressID string `json:"AddressID"`
	Body string `json:"Body"`
	Id string `json:"id"`
	AttachmentKeyPackets struct{

	} `json:"AttachmentKeyPackets"`
}

type MessageData struct {
	Message Message `json:"Message"`
}

type MessageResult struct {
	Code int `json:"Code"`
	Message struct {
		ID string `json:"ID"`
	} `json:"Message"`
}