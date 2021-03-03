package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/spf13/viper"
)

func main() {

	var err error

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err = viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}

	initSessionStore()

	if auth, err = newAuthenticator(); err != nil {
		log.Panic(err)
	}

	runServer()
}

var template = x509.Certificate{
	SerialNumber: big.NewInt(0),
	Subject: pkix.Name{
		CommonName: "localhost",
	},
	NotBefore: time.Now().Add(-time.Hour),
	NotAfter:  time.Now().Add(time.Hour),
}

func runServer() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := key.Public()
	crt, _ := x509.CreateCertificate(rand.Reader, &template, &template, pub, key)

	cert := tls.Certificate{
		Certificate: [][]byte{crt},
		PrivateKey:  key,
	}
	srv := &http.Server{
		Addr:      ":443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	http.HandleFunc("/login", login)
	http.HandleFunc("/callback", callback)
	http.Handle("/", isAuthenticated(secureHelloWorld()))
	log.Print("serving...")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func isLoggedIn(r *http.Request) (bool, error) {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		return false, err
	}

	_, ok := session.Values["claims"]
	return ok, nil
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var (
			err      error
			loggedIn bool
		)

		if loggedIn, err = isLoggedIn(r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !loggedIn {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secureHelloWorld() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-type", "text/html")
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		claims := session.Values["claims"].(claims)
		fmt.Fprintf(w, "<h3>Hello, %s.</h3>", claims.PreferredUsername)
		w.Write([]byte("<pre>"))
		w.Write(dumpSession(session.Values))
		w.Write([]byte("</pre>"))
	})
}
