package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

var (
	listenPort        string
	backendUrl        string
	rceRegex          = regexp.MustCompile(`(?i)(\bnet\b|\bshell\b|\bcmd\b|\bexec\b|\bspawn\b|\bpopen\b|\bpassthru\b|\bsystem\b|\bproc_open\b|\bwget\b|\bcurl\b|\bpasswd\b|\bsocket_connect\b|\bopen_basedir\b|\bdisable_functions\b|\bfile_get_contents\b|\bfile_put_contents\b|\bcopy\b|\bmove\b|\brename\b|\bdelete\b|\bshell_exec\b)`)
	sqlInjectionRegex = regexp.MustCompile(`(?i)(\bselect\b|\bupdate\b|\bdelete\b|\binsert\b|\breplace\b|\btruncate\b|\bcreate\b|\bdrop\b|\bunion\b|\bexec\b|\bsp_exec\b|\bxp_cmdshell\b|\bcall\b)\s+`)
)

func init() {
	flag.StringVar(&listenPort, "port", "9000", "the port to listen on, e.g., '9000'")
	flag.StringVar(&backendUrl, "backend", "http://127.0.0.1:8000", "the backend URL to proxy to, e.g., 'http://127.0.0.1:8000'")
}

func ParseFormCopy(req *http.Request) (url.Values, error) {
	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	reqForParse := *req
	reqForParse.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	if err := reqForParse.ParseForm(); err != nil {
		return nil, err
	}

	return reqForParse.PostForm, nil
}

func ParseMultiFormCopy(req *http.Request) (*multipart.Form, error) {
	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	reqForParse := *req
	reqForParse.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	if err := reqForParse.ParseMultipartForm(32 << 20); err != nil {
		return nil, err
	}

	req.MultipartForm = reqForParse.MultipartForm
	return reqForParse.MultipartForm, nil
}

func detectAttack(req *http.Request) bool {
	log.Println("-------Begin Detection---------")
	log.Printf("Request Method: %s, URL: %s", req.Method, req.URL)

	checkForAttacks := func(data string) bool {
		rceMatch := rceRegex.MatchString(data)
		sqlMatch := sqlInjectionRegex.MatchString(data)
		log.Printf("Checking data: %s", data)
		log.Printf("RCE Match: %v, SQL Injection Match: %v", rceMatch, sqlMatch)
		return rceMatch || sqlMatch
	}

	queryValues := req.URL.Query()
	for key, values := range queryValues {
		for _, value := range values {
			log.Printf("Checking query parameter: %s=%s", key, value)
			if checkForAttacks(value) {
				log.Printf("Attack detected in query parameter: %s=%s", key, value)
				return true
			}
		}
	}

	contentType := req.Header.Get("Content-Type")
	log.Printf("Content-Type: %s", contentType)

	if strings.Contains(contentType, "application/json") {
		var jsonData map[string]interface{}
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			log.Println("Error reading request body:", err)
			return false
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
			log.Println("Error unmarshalling JSON:", err)
			return false
		}

		for key, value := range jsonData {
			if strValue, ok := value.(string); ok {
				log.Printf("Checking JSON field: %s=%s", key, strValue)
				if checkForAttacks(strValue) {
					log.Printf("Attack detected in JSON field: %s=%s", key, strValue)
					return true
				}
			}
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data") {
		postForm, err := ParseFormCopy(req)
		if err != nil {
			log.Println("Error parsing form data:", err)
			return false
		}

		for key, values := range postForm {
			for _, value := range values {
				log.Printf("Checking form field: %s=%s", key, value)
				if checkForAttacks(value) {
					log.Printf("Attack detected in form field: %s=%s", key, value)
					return true
				}
			}
		}

		MultipartForm, err := ParseMultiFormCopy(req)
		if MultipartForm != nil {
			for key, files := range MultipartForm.File {
				for _, fileHeader := range files {
					log.Printf("Checking uploaded file: %s (filename: %s)", key, fileHeader.Filename)
					if strings.HasSuffix(fileHeader.Filename, ".jsp") || strings.HasSuffix(fileHeader.Filename, ".php") {
						log.Printf("Potentially dangerous file detected: %s", fileHeader.Filename)
						return true
					}
				}
			}

			for key, fields := range MultipartForm.Value {
				for _, value := range fields {
					log.Printf("Checking multipart form field: %s=%s", key, value)
					if checkForAttacks(value) {
						log.Printf("Attack detected in multipart form field: %s=%s", key, value)
						return true
					}
				}
			}
		} else {
			log.Println("Error parsing multipart form")
		}
	}

	log.Println("-------End Detection---------")
	return false
}

func main() {
	flag.Parse()

	backend, err := url.Parse(backendUrl)
	if err != nil {
		log.Fatalf("Error parsing backend URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)

	server := &http.Server{
		Addr: ":" + listenPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if detectAttack(r) {
				log.Println("-------Attack Detected---------")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}

	log.Printf("Listening on :%s and proxying to %s", listenPort, backendUrl)
	log.Fatal(server.ListenAndServe())
}
