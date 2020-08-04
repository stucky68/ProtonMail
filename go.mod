module ProtonMail

go 1.13

require (
	github.com/ProtonMail/gopenpgp/v2 v2.0.1
	github.com/jameskeane/bcrypt v0.0.0-20120420032655-c3cd44c1e20f
	github.com/katzenpost/core v0.0.11 // indirect
	github.com/panjf2000/ants/v2 v2.4.1
	golang.org/x/crypto v0.0.0-20200429183012-4b2356b1ed79
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c
