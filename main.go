package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

func main() {
	r := chi.NewRouter()
	r.MethodFunc(http.MethodPost, "/v1/signin", Signin)

	log.Panic(http.ListenAndServe("localhost:8080", r))
}

var validUser = &User{
	ID:           10,
	Email:        "foo@example.com",
	PasswordHash: "$2a$08$0xDi9HAxG4dfpzXzXgEMB.Lb3UrTPyRaOoUW57yuFT2OYxJ5NzoDK",
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Signin(w http.ResponseWriter, r *http.Request) {

	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Cannot decode request body: credentials", http.StatusInternalServerError)
		return
	}

	hashedPassword := validUser.PasswordHash

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256,
		jwt.MapClaims{
			// https://datatracker.ietf.org/doc/html/rfc7519
			// 以下はRegistered Claim
			"sub": fmt.Sprint(validUser.ID),                           // Subject: JWTの主語。issuerごとに or グローバルにユニーク
			"iat": jwt.NewNumericDate(time.Now()),                     // Issued At: JWTの発行日時
			"nbf": jwt.NewNumericDate(time.Now()),                     // Not Before: JWTが有効になる日時
			"exp": jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Expiration Time: JWTが失効する日時
			"iss": "mydomain.com",                                     // Issuer: JWTの発行者。このクレームの処理はクライアントアプリに依存
			"aud": []string{"mydomain.com"},                           // Audiance: JWTの利用者。利用者が自分で想定している値が入っていなかったらリジェクトする
			// Public Claim
			// https://www.iana.org/assignments/jwt/jwt.xhtml
			"email": "foo@example.com",
		})

	keyBytes, err := ioutil.ReadFile(os.Getenv("PRIVATE_KEY_FILE_PATH"))
	if err != nil {
		http.Error(w, "Cannot read private key file", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(keyBytes)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "Error parse privatekey", http.StatusInternalServerError)
	}

	s, err := t.SignedString(key)
	if err != nil {
		http.Error(w, "Error signing", http.StatusInternalServerError)
		return
	}

	dataArray := strings.Split(s, ".")
	header, payload, sig := dataArray[0], dataArray[1], dataArray[2]

	pkBytes, err := ioutil.ReadFile(os.Getenv("PUBLIC_KEY_FILE_PATH"))
	if err != nil {
		http.Error(w, "Cannot read public key file", http.StatusInternalServerError)
		return
	}

	pubBlock, _ := pem.Decode(pkBytes)
	pk, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
	if err != nil {
		http.Error(w, "Error parse publickey", http.StatusInternalServerError)
	}

	headerData, err := base64.RawStdEncoding.DecodeString(header)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	payloadData, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	message := sha256.Sum256([]byte(header + "." + payload))

	sigData, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, message[:], sigData); err != nil {
		fmt.Println("invalid token")
	} else {
		fmt.Println("valid token")
		fmt.Println("header: ", string(headerData))
		fmt.Println("payload: ", string(payloadData))
	}

	json.NewEncoder(w).Encode(s)
}
