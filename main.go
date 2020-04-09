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

	router := httprouter.New()

  router.GET("/hello-if", helloIframe)
  router.GET("/hello-wh", helloWithHeaders)
  router.GET("/hello-ns", helloNoSniff)

  router.GET("/hello-ct", helloContentType)
  router.GET("/hello-csp2", helloContentSecurityPolicy2)
  router.GET("/hello-csp", helloContentSecurityPolicy)
  router.GET("/hello", hello)

	log.Info("Service is ready to listen and serve.")

  if err := http.ListenAndServe(":8000", router); err != nil {
    log.Panic(err)
  }

  log.Info("Done :D ")

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

    // Get XSS Attack
    getXss(w, r)
}

// helloContentSecurityPolicy2 returns
func helloContentSecurityPolicy2(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    w.Header().Set("Content-Security-Policy",
      `default-src
        'self';
      script-src
        'self'
        https://cdnjs.cloudflare.com;
      img-src
        'self'
        https://i.picsum.photos/
        https://picsum.photos/;
      `)

    // Get XSS Attack
    getXss(w, r)

    //Load third party library script-src
    loadSrc := `<script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>`
    fmt.Fprintf(w, "%s\n", loadSrc)

    //Load third party image source src
    imgSrc := `https://picsum.photos/id/237/200/300`
    loadImg := fmt.Sprintf(`<img src="%s" alt="Smiley face" height="300" width="200">`, imgSrc)

    fmt.Fprintf(w, "%s\n", loadImg)
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

    iframe := "<iframe height='300px' width='100%' src='http://nfl.com/'></iframe>"

    fmt.Fprintf(w, "%s\n", iframe)
    fmt.Fprintf(w, "Processing URL %s...\n", r.URL.Path)
}

// helloWithHeaders returns
func helloWithHeaders(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

    w.Header().Set("Content-Type", "application/json;")
    w.Header().Add("X-Content-Type-Options", "nosniff")

    getXss(w, r)
}
