package conf

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

type ServiceLevels struct {
	Dscp     int      `json:"dscp"`
	Patterns []string `json:"patterns"`
	LeadDscp  int `json:"leadDscp"`
	LeadBytes int`json:"leadBytes"`

}

type Conf struct {
	DefaultDscp int             `json:"defaultDscp"`
	Levels      []ServiceLevels `json:"levels"`
	LogLevel    logrus.Level    `json:"logLevel"`
	BindSocket  string          `json:"bindSocket"`
}

func LoadConf(confPath string) (*Conf, error) {

	if envConfPath, ok := os.LookupEnv("TLS_PROXY_CONF_PATH"); ok {
		confPath = envConfPath
	}
	confFile, err := os.Open(confPath)

	if err != nil {
		return nil, err
	}

	var conf *Conf = &Conf{
		LogLevel:   logrus.InfoLevel,
		BindSocket: ":443",
	}
	jsonParser := json.NewDecoder(confFile)
	err = jsonParser.Decode(conf)

	confFile.Close()

	if err != nil {
		return nil, err
	}

	if (conf.DefaultDscp < 0) || (conf.DefaultDscp >= 64) {
		return nil, fmt.Errorf("default DSCP %d is not valid", conf.DefaultDscp)
	}

	for _, lvl := range conf.Levels {
		if (lvl.Dscp < 0) || (lvl.Dscp >= 64) {
			return nil, fmt.Errorf("inavlid DSCP %d", lvl.Dscp)
		}
	}

	return conf, nil
}
