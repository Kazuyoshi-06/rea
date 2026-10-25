package main

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/text/language"
)

func main() {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "rea"})
	s, err := tok.SignedString([]byte("k"))
	if err != nil {
		panic(err)
	}
	fmt.Println(s, language.MustParse("fr-FR"))
}
