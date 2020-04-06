package main

import (
  "fmt"
	"net/http"
	_ "os"

	"github.com/sirupsen/logrus"
  "github.com/julienschmidt/httprouter"

)

var log = logrus.New()

// Run server: go build -o app && ./app
// Try requests: curl http://127.0.0.1:8000/
func main() {
	log.Info("Initialize service...")

	// port := os.Getenv("PORT")
	// if len(port) == 0 {
	// 	log.Fatal("Required parameter service port is not set")
	// }
  //
	router := httprouter.New()

  router.GET("/hello-if", helloIframe)
  router.GET("/hello-wh", helloWithHeaders)
  router.GET("/hello-ns", helloNoSniff)
  router.GET("/hello-ct", helloContentType)
  router.GET("/hello-csp", helloContentSecurityPolicy)
  router.GET("/hello", hello)

	log.Info("Service is ready to listen and serve.")
	http.ListenAndServe(":8000", router)
}

func getXss(w http.ResponseWriter, r *http.Request) {
    xss := "<script>alert(1);</script>"
    fmt.Fprintf(w, "%s\n", xss)
    fmt.Fprintf(w, "Processing URL %s...\n", r.URL.Path)
}

// hello returns
func hello(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    getXss(w, r)
}

// helloContentSecurityPolicy returns
func helloContentSecurityPolicy(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    w.Header().Set("Content-Security-Policy", "default-src 'self';")
    getXss(w, r)
}

// helloContentType returns
func helloContentType(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    w.Header().Set("Content-Type", "application/json;")
    getXss(w, r)
}

// helloNoSniff returns
func helloNoSniff(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    w.Header().Add("X-Content-Type-Options", "nosniff")
    getXss(w, r)
}

// helloIframe returns
func helloIframe(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    iframe := "<iframe height='300px' width='100%' src='https://haveibeenpwned.com/'></iframe>"

    fmt.Fprintf(w, "%s\n", iframe)
    fmt.Fprintf(w, "Processing URL %s...\n", r.URL.Path)
}

// helloWithHeaders returns
func helloWithHeaders(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    w.Header().Set("Content-Type", "application/json;")
    w.Header().Add("X-Content-Type-Options", "nosniff")

    getXss(w, r)
}
