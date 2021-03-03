package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

func login(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	loggedIn, err := isLoggedIn(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if loggedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	if r.FormValue("do") == "true" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state := base64.StdEncoding.EncodeToString(b)
		session.Values["state"] = state
		if err = session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, auth.config.AuthCodeURL(state), http.StatusFound)
		return
	}

	w.Header().Add("Content-type", "text/html")
	fmt.Fprint(w, `
<form action="/login" method="get">
<input type="hidden" name="do" value="true"/>
<button type="submit">Login</button></form>`)
}
