package client

import "net/http"

type AuthRoundTripper struct {
	DefaultRoundTripper http.RoundTripper
	Username            string
	Token               string
}

func (art AuthRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Add("username", art.Username)
	r.Header.Add("token", art.Token)
	return art.DefaultRoundTripper.RoundTrip(r)
}
