module ProtonMail

go 1.13

require (
	github.com/ProtonMail/gopenpgp/v2 v2.0.1
	github.com/jameskeane/bcrypt v0.0.0-20120420032655-c3cd44c1e20f
	github.com/kr/pretty v0.1.0 // indirect
	github.com/panjf2000/ants/v2 v2.4.1
	golang.org/x/crypto v0.0.0-20200429183012-4b2356b1ed79
	golang.org/x/sys v0.0.0-20200501145240-bc7a7d42d5c3 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c
