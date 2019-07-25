package digestauth

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Digest struct {
	URL        string
	Username   string
	Password   string
	Realm      string
	Nonce      string
	CNonce     string
	NonceCount string
	Qop        string
	Domain     string
	Algorithm  string
	Method     string
	HA1        string
	HA2        string
	Res        string
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func StringWithCharset(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// func StringWithCharset(length int, charset string) string {
// 	b := make([]byte, length)
// 	for i := range b {
// 		b[i] = charset[rand.Intn(len(charset))]
// 	}
// 	return string(b)
// }

func (self *Digest) ha1() string {
	data := []byte(self.Username + ":" + self.Realm + ":" + self.Password)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func (self *Digest) ha2() string {
	data := []byte(self.Method + ":" + self.Domain)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func (self *Digest) Response() string {
	data := []byte(self.HA1 + ":" + self.Nonce + ":" + self.NonceCount + ":" + self.CNonce + ":" + self.Qop + ":" + self.HA2)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func (self *Digest) GetRespUnAuth(url string) *http.Response {
	self.URL = url

	request, err := http.NewRequest("GET", self.URL, nil)

	timeout := time.Duration(10 * time.Second)

	client := http.Client{
		Timeout: timeout,
	}

	if err != nil {
		log.Println(err)
	}

	response, err := client.Do(request)

	if err != nil {
		log.Println(err)
	}

	return response
}

func (self *Digest) GetRespDigest(response *http.Response) *http.Response {
	resAuth := response.Header["Www-Authenticate"][0]
	//fmt.Println(resAuth)

	resAuth_arr := strings.Split(resAuth, ",")

	if len(resAuth_arr) == 5 {
		resAuthArr := strings.Split(resAuth, ",")
		self.Realm = strings.Split(resAuthArr[0], "\"")[1]
		self.Domain = strings.Split(self.URL, ":8087")[1]
		self.Nonce = strings.Split(resAuthArr[2], "\"")[1]
		self.Algorithm = strings.Split(resAuthArr[3], "=")[1]
		self.Qop = strings.Split(resAuthArr[4], "\"")[1]
		self.CNonce = StringWithCharset(8)
		self.NonceCount = "00000001"
	} else {
		self.Realm = strings.Split(resAuth_arr[0], "\"")[1]
		self.Domain = strings.Split(self.URL, ":8086")[1]
		self.Nonce = strings.Split(resAuth_arr[1], "\"")[1]
		self.Algorithm = strings.Split(resAuth_arr[2], "=")[1]
		self.Qop = strings.Split(resAuth_arr[3], "\"")[1]
		self.CNonce = StringWithCharset(8)
		self.NonceCount = "00000001"
	}

	// fmt.Println(self.Realm, self.Domain, self.Nonce, self.Algorithm, self.Qop)
	// fmt.Println(response.Header["Www-Authenticate"])

	self.HA1 = self.ha1()
	self.HA2 = self.ha2()

	// fmt.Println(self.HA1)
	// fmt.Println(self.HA2)

	self.Res = self.Response()
	//hex.EncodeToString(h.Sum(nil))

	// fmt.Println(self.Res)

	timeout := time.Duration(10 * time.Second)

	client := http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", self.URL, nil)

	if err != nil {
		log.Println(err)
	}

	auth := "Digest username=\"" + self.Username + "\", realm=\"" + self.Realm + "\", nonce=\"" + self.Nonce + "\", uri=\"" + self.Domain + "\", algorithm=\"" + self.Algorithm + "\", qop=" + self.Qop + ", nc=" + self.NonceCount + ", cnonce=\"" + self.CNonce + "\", response=\"" + self.Res + "\""

	// fmt.Println(auth)
	req.Header.Add("Authorization", auth)
	res, err := client.Do(req)

	if err != nil {
		log.Println(err)
	}

	return res
}

func (self *Digest) GetInfo(url, username, password, method string) ([]byte, error) {
	self.Username = username
	self.Password = password
	self.Method = method

	//fmt.Println(url, self.Username, self.Password)

	response := self.GetRespUnAuth(url)

	//fmt.Println(response)

	//fmt.Println(len(response.Header["Www-Authenticate"]))

	if response != nil {
		defer response.Body.Close()
		if len(response.Header["Www-Authenticate"]) != 0 {

			//fmt.Println(response.Header["Www-Authenticate"])
			res := self.GetRespDigest(response)

			defer res.Body.Close()

			body, err := ioutil.ReadAll(res.Body)

			if err != nil {
				log.Println(err)
			}

			if res.StatusCode != 200 {
				return nil, errors.New(self.URL + " status code = " + strconv.Itoa(response.StatusCode))
			}
			return body, nil

		}

		body, err := ioutil.ReadAll(response.Body)

		if err != nil {
			log.Println(err)
		}

		//fmt.Println(string(body))
		if response.StatusCode != 200 {
			return nil, errors.New(self.URL + " status code = " + strconv.Itoa(response.StatusCode))
		}
		return body, nil
	}

	return nil, errors.New(self.URL + " cannot connected")

}
