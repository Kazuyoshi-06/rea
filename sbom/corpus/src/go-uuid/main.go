package main

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.WithField("id", uuid.NewString()).Info("hello")
	fmt.Println("ok")
}
