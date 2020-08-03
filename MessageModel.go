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
	Error string `json:"Error"`
	Message struct {
		ID string `json:"ID"`
		Body string `json:"Body"`
	} `json:"Message"`
}

type SendMessageAddresses struct {
	Type int `json:"Type"`
	Signature int `json:"Signature"`
}

type SendMeesagePackages struct {
	Flags int `json:"Flags"`
	Addresses map[string]SendMessageAddresses `json:"Addresses"`
	MIMEType string `json:"MIMEType"`
	Body string `json:"Body"`
	Type int `json:"Type"`
	AttachmentKeys struct{
	} `json:"AttachmentKeys"`
	BodyKey struct {
		Key string `json:"Key"`
		Algorithm string `json:"Algorithm"`
	} `json:"BodyKey"`
}

type SendMessageData struct {
	Id string `json:"id"`
	Packages[] SendMeesagePackages `json:"Packages"`
}