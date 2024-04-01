module github.com/21a1ss3/tlsSniProxy

go 1.21.6

require (
	github.com/21a1ss3/goPatchedTls v0.0.2
	github.com/sirupsen/logrus v1.9.3
)

require (
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/21a1ss3/goPatchedTls => github.com/21a1ss3/goPatchedTls v0.0.2
