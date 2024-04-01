package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

var A *logrus.Logger //Agent

func InitLog() {
	A = logrus.New()
	A.SetOutput(os.Stdout)
	A.SetLevel(logrus.InfoLevel)
}
