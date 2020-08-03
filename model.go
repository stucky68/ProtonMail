package main

type GetInfoResult struct {
	Code int `json:"Code"`
	Modulus string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Version int `json:"Version"`
	Salt string `json:"Salt"`
	SRPSession string `json:"SRPSession"`
}

type AuthData struct {
	ClientEphemeral string `json:"ClientEphemeral"`
	ClientProof string `json:"ClientProof"`
	SRPSession string `json:"SRPSession"`
	Username string `json:"Username"`
}

type AuthResult struct {
	AccessToken string `json:"AccessToken"`
	Code int `json:"Code"`
	EventID string `json:"EventID"`
	ExpiresIn int `json:"ExpiresIn"`
	LocalID int `json:"LocalID"`
	PasswordMode int `json:"PasswordMode"`
	RefreshToken string `json:"RefreshToken"`
	Scope string `json:"Scope"`
	ServerProof string `json:"ServerProof"`
	TokenType string `json:"TokenType"`
	TwoFactor int `json:"TwoFactor"`
	UID string `json:"UID"`
	Uid string `json:"Uid"`
	UserID string `json:"UserID"`
}

type UserResult struct {
	Code int `json:"Code"`
	User struct {
		ID          string `json:"ID"`
		Name        string `json:"Name"`
		UsedSpace   int    `json:"UsedSpace"`
		Currency    string `json:"Currency"`
		Credit      int    `json:"Credit"`
		MaxSpace    int    `json:"MaxSpace"`
		MaxUpload   int    `json:"MaxUpload"`
		Subscribed  int    `json:"Subscribed"`
		Services    int    `json:"Services"`
		Role        int    `json:"Role"`
		Private     int    `json:"Private"`
		Delinquent  int    `json:"Delinquent"`
		Email       string `json:"Email"`
		DisplayName string `json:"DisplayName"`
	} `json:"User"`

	Keys[] struct {
		Fingerprint string `json:"Fingerprint"`
		ID string `json:"ID"`
		Primary int `json:"Primary"`
		PrivateKey string `json:"PrivateKey"`
		Version int `json:"Version"`
	} `json:"Keys"`
}

type CookiesData struct {
	AccessToken string `json:"AccessToken"`
	GrantType string `json:"GrantType"`
	RedirectURI string `json:"RedirectURI"`
	RefreshToken string `json:"RefreshToken"`
	ResponseType string `json:"ResponseType"`
	State string `json:"State"`
	UID string `json:"UID"`
}

type AddressResult struct {
	Code int `json:"Code"`
	Addresses[] struct{
		ID string `json:"ID"`
		DomainID string `json:"DomainID"`
		Email string `json:"Email"`
		Status int `json:"Status"`
		Type int `json:"Type"`
		Receive int `json:"Receive"`
		Send int `json:"Send"`
		DisplayName string `json:"DisplayName"`
		Signature string `json:"Signature"`
		Order int `json:"Order"`
		Priority int `json:"Priority"`
		HasKeys int `json:"HasKeys"`
		SignedKeyList string `json:"SignedKeyList"`
		Keys[] struct {
			ID string `json:"ID"`
			Primary int `json:"Primary"`
			Flags int `json:"Flags"`
			Fingerprint string `json:"Fingerprint"`
			Fingerprints[] string `json:"Fingerprints"`
			PublicKey string `json:"PublicKey"`
			Active int `json:"Active"`
			Version int `json:"Version"`
			Activation string `json:"Activation"`
			PrivateKey string `json:"PrivateKey"`
			Token string `json:"Token"`
			Signature string `json:"Signature"`
		} `json:"Keys"`
	} `json:"Addresses"`
}


