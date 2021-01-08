/*
Copyright 2016 Medcl (m AT medcl.net)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"net"
	"net/http"
	uri "net/url"
	"os"
	"strings"
	"time"
	"math"

	"crypto/tls"
	"fmt"
	"io"

	log "github.com/cihub/seelog"
	"github.com/dan-drl/framework/core/errors"
	"golang.org/x/net/proxy"

	"encoding/json"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	Verb_GET    string = "GET"
	Verb_PUT    string = "PUT"
	Verb_POST   string = "POST"
	Verb_DELETE string = "DELETE"
	Verb_HEAD   string = "HEAD"
)

var lumberjack_log lumberjack.Logger
var logWebRequests = os.Getenv("GOPA_LOG_WEB_REQUESTS") == "true"

func init() {
	if logWebRequests {
		lumberjack_log = lumberjack.Logger{
			Filename:   "/var/log/gopa/webrequests.log",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     1,
			Compress:   false,
		}
	}
}

// GetHost return the host from a url
func GetHost(url string) string {

	if strings.HasPrefix(url, "//") {
		url = strings.TrimLeft(url, "//")
	}

	array := strings.Split(url, ".")
	if len(array) > 0 {
		t := array[len(array)-1]
		isTLD := IsValidTLD(t)
		if isTLD {
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
		}
	}

	if strings.Contains(url, "/") {
		if !strings.HasPrefix(url, "http") {
			url = "http://" + url
		}
	}

	uri, err := uri.Parse(url)
	if err != nil {
		log.Trace(err)
		return ""
	}

	return uri.Host
}

//GetRootUrl parse to get url root
func GetRootUrl(source *uri.URL) string {
	if strings.HasSuffix(source.Path, "/") {
		return source.Host + source.Path
	}

	index := strings.LastIndex(source.Path, "/")
	if index > 0 {
		path := source.Path[0:index]
		return source.Host + path
	}

	return source.Host + "/"
}

//FormatUrlForFilter format url, normalize url
func formatUrlForFilter(url []byte) []byte {
	src := string(url)
	log.Trace("start to normalize url:", src)
	if strings.HasSuffix(src, "/") {
		src = strings.TrimRight(src, "/")
	}
	src = strings.TrimSpace(src)
	src = strings.ToLower(src)
	return []byte(src)
}

func getUrlPathFolderWithoutFile(url []byte) []byte {
	src := string(url)
	log.Trace("start to get url's path folder:", src)
	if strings.HasSuffix(src, "/") {
		src = strings.TrimRight(src, "/")
	}
	src = strings.TrimSpace(src)
	src = strings.ToLower(src)
	return []byte(src)
}

func getUrl(url string) (string, error) {
	if !strings.HasPrefix(url, "http") {
		return url, errors.New("invalid url, " + url)
	}
	return url, nil
}

type Request struct {
	Agent       string
	Method      string
	Url         string
	Cookie      string
	Proxy       string
	Body        []byte
	StrBody     string
	headers     map[string]string
	ContentType string

	basicAuthUsername string
	basicAuthPassword string
}

// Hack in log function for capturing requests going to elastic search.
// These get logged to disk and filebeats sends them out.

// func GetUUID() string {
// 	b := make([]byte, 16)
// 	_, err := rand.Read(b)
// 	if err != nil {
//     log.Fatal(err)
// 	}
// 	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
//     b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
// 	}
// 	return uuid
// }

type ReqLog struct {
	Id     string    `json:"id,omitempty"`
	Name   string    `json:"name:omitempty"`
	Time   time.Time `json:"time,omitempty"`
	Type   string    `json:"type,omitempty"`
	Url    string    `json:"url,omitempty"`
	Method string    `json:"method,omitempty"`
	Body   string    `json:"body,omitempty"`
	Size   int       `json:"bodySize,omitempty"`
}

func (r *Request) Log() string {

	if !logWebRequests {
		return ""
	}

	id := GetUUID()
	json, _ := json.Marshal(ReqLog{Id: id, Name: "crawler", Time: time.Now().UTC(), Type: "Request", Url: r.Url, Method: r.Method, Body: string(r.Body), Size: len(r.Body)})
	lumberjack_log.Write([]byte(string(json) + "\n"))
	return id
}

type ResultLog struct {
	Id        string    `json:"id,omitempty"`
	Name      string    `json:"name,omitempty"`
	RequestId string    `json:"req_id,omitempty"`
	Time      time.Time `json:"time,omitempty"`
	Type      string    `json:"type,omitempty"`
	Status    int       `json:"status,omitempty"`
	Url       string    `json:"url,omitempty"`
	Body      string    `json:"body,omitempty"`
	Size      uint64    `json:"bodySize,omitempty"`
}

func (r *Result) Log(requestId string) string {

	if !logWebRequests {
		return ""
	}

	id := GetUUID()
	json, _ := json.Marshal(ResultLog{Id: id, Name: "crawler", RequestId: requestId, Time: time.Now().UTC(), Type: "Response", Url: r.Url, Body: string(r.Body), Status: r.StatusCode, Size: r.Size})
	lumberjack_log.Write([]byte(string(json) + "\n"))
	return id
}

func NewRequest(method, url string) *Request {
	req := Request{}
	req.Url = url
	req.Method = method
	return &req
}

// NewPostRequest issue a simple http post request
func NewPostRequest(url string, body []byte) *Request {
	req := Request{}
	req.Url = url
	req.Method = Verb_POST
	if body != nil {
		req.Body = body
	}
	return &req
}

// NewPutRequest issue a simple http put request
func NewPutRequest(url string, body []byte) *Request {
	req := Request{}
	req.Url = url
	req.Method = Verb_PUT
	if body != nil {
		req.Body = body
	}
	return &req
}

// NewGetRequest issue a simple http get request
func NewGetRequest(url string, body []byte) *Request {
	req := Request{}
	req.Url = url
	if body != nil {
		req.Body = body
	}
	req.Method = Verb_GET
	return &req
}

// NewDeleteRequest issue a simple http delete request
func NewDeleteRequest(url string, body []byte) *Request {
	req := Request{}
	req.Url = url
	if body != nil {
		req.Body = body
	}
	req.Method = Verb_DELETE
	return &req
}

// SetBasicAuth set user and password for request
func (r *Request) SetBasicAuth(username, password string) *Request {
	r.basicAuthUsername = username
	r.basicAuthPassword = password
	return r
}

func (r *Request) SetContentType(contentType string) *Request {
	r.ContentType = contentType
	return r
}

func (r *Request) AddHeader(key, v string) *Request {
	if r.headers == nil {
		r.headers = map[string]string{}
	}
	r.headers[key] = v
	return r
}

func (r *Request) SetAgent(agent string) *Request {
	r.Agent = agent
	return r
}

func (r *Request) AcceptGzip() *Request {
	r.AddHeader("Accept-Encoding", "gzip")
	return r
}

func (r *Request) SetProxy(proxy string) *Request {
	r.Proxy = proxy
	return r
}

// Result is the http request result
type Result struct {
	Host       string
	Url        string
	Headers    map[string][]string
	Body       []byte
	StatusCode int
	Size       uint64
}



const userAgent = "Mozilla/5.0 (compatible; DRL/1.0; +http://github.com/dan-drl/framework)"

const ContentTypeJson = "application/json;charset=utf-8"
const ContentTypeXml = "application/xml;charset=utf-8"
const ContentTypeForm = "application/x-www-form-urlencoded;charset=UTF-8"

// ExecuteRequest issue a request
func ExecuteRequest(req *Request) (result *Result, err error) {
	var request *http.Request
	if req.Body != nil && len(req.Body) > 0 {
		postBytesReader := bytes.NewReader(req.Body)
		request, err = http.NewRequest(string(req.Method), req.Url, postBytesReader)
	} else {
		request, err = http.NewRequest(string(req.Method), req.Url, nil)
	}

	if err != nil {
		panic(err)
	}

	if req.Agent != "" {
		request.Header.Set("User-Agent", req.Agent)
	} else {
		request.Header.Set("User-Agent", userAgent)
	}

	//request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	//request.Header.Set("Accept-Charset", "GBK,utf-8;q=0.7,*;q=0.3")
	//request.Header.Set("Accept-Encoding", "gzip,deflate,sdch")

	if req.ContentType != "" {
		request.Header.Add("Content-Type", req.ContentType)
	}

	//request.Header.Set("Cache-Control", "max-age=0")
	//request.Header.Set("Connection", "keep-alive")
	request.Header.Set("Referer", req.Url)

	if req.headers != nil {
		for k, v := range req.headers {
			request.Header.Set(k, v)
		}
	}

	if req.Cookie != "" {
		log.Debug("dealing with cookie:" + req.Cookie)
		array := strings.Split(req.Cookie, ";")
		for item := range array {
			array2 := strings.Split(array[item], "=")
			if len(array2) == 2 {
				cookieObj := http.Cookie{}
				cookieObj.Name = array2[0]
				cookieObj.Value = array2[1]
				request.AddCookie(&cookieObj)
			} else {
				log.Info("error,index out of range:" + array[item])
			}
		}
	}

	if req.basicAuthUsername != "" && req.basicAuthPassword != "" {
		request.SetBasicAuth(req.basicAuthUsername, req.basicAuthPassword)
	}

	if req.Proxy != "" {
		// Create a transport that uses Tor Browser's SocksPort.  If
		// talking to a system tor, this may be an AF_UNIX socket, or
		// 127.0.0.1:9050 instead.
		tbProxyURL, err := uri.Parse(req.Proxy)
		if err != nil {
			panic(err)
			return nil, fmt.Errorf("Failed to parse proxy URL: %v", err)
		}

		// Get a proxy Dialer that will create the connection on our
		// behalf via the SOCKS5 proxy.  Specify the authentication
		// and re-create the dialer/transport/client if tor's
		// IsolateSOCKSAuth is needed.
		tbDialer, err := proxy.FromURL(tbProxyURL, proxy.Direct)
		if err != nil {
			panic(err)
			return nil, fmt.Errorf("Failed to obtain proxy dialer: %v", err)
		}

		// Make a http.Transport that uses the proxy dialer, and a
		// http.Client that uses the transport.
		tbTransport := &http.Transport{
			Dial: tbDialer.Dial,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		}
		client.Transport = tbTransport
	}

	return executeWithBackoff(&(Backoff{ EXP, time.Second, 0, 10}), request, req)

}

// HttpGetWithCookie issue http request with cookie
func HttpGetWithCookie(resource string, cookie string, proxy string) (*Result, error) {
	req := NewGetRequest(resource, nil)
	if cookie != "" {
		req.Cookie = cookie
	}
	if proxy != "" {
		req.Proxy = proxy
	}
	return ExecuteRequest(req)
}

// HttpGet issue a simple http get request
func HttpGet(resource string) (*Result, error) {
	req := NewGetRequest(resource, nil)
	return ExecuteRequest(req)
}

// HttpDelete issue a simple http delete request
func HttpDelete(resource string) (*Result, error) {
	req := NewDeleteRequest(resource, nil)
	return ExecuteRequest(req)
}

var timeout = 30 * time.Second
var t = &http.Transport{
	Dial: func(netw, addr string) (net.Conn, error) {
		deadline := time.Now().Add(30 * time.Second)
		c, err := net.DialTimeout(netw, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}
		c.SetDeadline(deadline)
		return c, nil
	},
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext,
	ResponseHeaderTimeout: timeout,
	IdleConnTimeout:       timeout,
	TLSHandshakeTimeout:   timeout,
	ExpectContinueTimeout: timeout,
	DisableCompression:    true,
	DisableKeepAlives:     false,
	MaxIdleConns:          20000,
	MaxIdleConnsPerHost:   20000,
	MaxConnsPerHost:       20000,
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
}

var client = &http.Client{
	Transport:     t,
	Timeout:       timeout,
	CheckRedirect: nil,
}


type BackoffType int32

const (
	LINEAR BackoffType = iota
	EXP
)

type Backoff struct {
	Type			BackoffType
	Interval  time.Duration
	curTry    int
	maxTry    int
}

func executeWithBackoff(backoff *Backoff, req *http.Request, baseReq *Request) (res *Result, err error) {

	defer func() {

		// As long as try is less than max allowed tries, take error from panic, and try again. 
		// Once tries exceeds max tries, panic will bubble up and potentially crash program.
		if backoff.curTry < backoff.maxTry {

			// Handle panic
			if r := recover(); r != nil {
				log.Debug("Recovering from panic during execute")
				var ok bool
				err, ok = r.(error)
				if !ok {
					err = fmt.Errorf("pkg: %v", r)
				}
			}
		}
	}()

	// Attempt to execute the request
	res, err = execute(req, baseReq)

	// If there was an error, and still under max tries limit make a recursive call to try request again. 
	if err != nil && backoff.curTry < backoff.maxTry {
		log.Debugf("Recover attempt %i of %i. Encountered error.", backoff.curTry, backoff.maxTry)
		log.Error("Recovering from", err)
		

		// Sleep for specified interval
		if backoff.Type == LINEAR {
			log.Debugf("Sleeping for %i", backoff.Interval)
			time.Sleep(backoff.Interval)
		} else if backoff.Type == EXP {
			exp := math.Pow(2, float64(backoff.curTry))
			dur := backoff.Interval * time.Duration(exp)

			log.Debugf("Sleeping for %i", dur)
			time.Sleep(dur)
		}

		// Try again
		backoff.curTry = backoff.curTry + 1
		res, err = executeWithBackoff(backoff, req, baseReq)
	}

	return res, err
}

func execute(req *http.Request, baseReq *Request) (*Result, error) {

	// Log the request
	requestId := baseReq.Log()

	result := &Result{}
	resp, err := client.Do(req)

	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if err != nil {
		panic(err)
		//return result, err
	}

	if resp != nil {
		statusCode := resp.StatusCode
		result.StatusCode = statusCode

		if statusCode == 301 || statusCode == 302 {

			log.Debug("got redirect: ", req.URL, " => ", resp.Header.Get("Location"))
			location := resp.Header.Get("Location")
			if len(location) > 0 && location != req.URL.String() {
				return result, errors.NewWithPayload(err, errors.URLRedirected, location, fmt.Sprint("got redirect: ", req.URL, " => ", location))
			}
		}

		// update host, redirects may change the host
		result.Host = resp.Request.Host
		result.Url = resp.Request.URL.String()
	}

	if resp.Header != nil {

		result.Headers = map[string][]string{}
		for k, v := range resp.Header {
			result.Headers[strings.ToLower(k)] = v
		}
	}

	reader := resp.Body

	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(resp.Body)

		if err != nil {
			panic(err)
		}
	}

	if reader != nil {
		body, err := ioutil.ReadAll(reader)
		io.Copy(ioutil.Discard, reader)
		reader.Close()
		if err != nil {
			panic(err)
		}

		result.Body = body
		result.Size = uint64(len(body))

		// Log the response
		result.Log(requestId)

		return result, nil
	}

	return nil, http.ErrNotSupported
}
