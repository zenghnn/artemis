package artemis

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"strconv"
	"time"
)

var ARTEMIS_PATH string = "/artemis"
var HOST = "192.168.3.15"
var path = "https://" + HOST + ARTEMIS_PATH
var AppKey = "AFDSFASDG"
var AppSecret = "FSDF"

func Post(uri string, data map[string]interface{}) (body []byte, err error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}}
	//JSON序列化
	configData, _ := json.Marshal(data)
	param := bytes.NewBuffer([]byte(configData))

	// 获取 request请求
	request, err := http.NewRequest("POST", path+uri, param)

	if err != nil {
		//zlog.GetLogger().Error("Post Request Error:", err)
		return nil, nil
	}
	// 加入 token
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json;charset=UTF-8")
	resp, err := client.Do(request)
	if err != nil {
		//zlog.GetLogger().Error("Post Response Error:", err)
		return nil, nil
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	defer client.CloseIdleConnections()
	return body, nil
}

func PostForm(uri string, data interface{}) (body []byte, err error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}}
	//JSON序列化
	configData, _ := json.Marshal(data)
	//fmt.Printf("-->>rawdata:%s \n", string(RawMessage))
	param := bytes.NewBuffer(configData)
	//fmt.Println("----md5 -->", dataMd5)
	// 获取 request请求
	request, err := http.NewRequest("POST", path+uri, param)
	//request.Form = form
	if err != nil {
		//zlog.GetLogger().Error("Artemis生成request错误:", err)
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	// 组织header
	header := map[string]string{}
	header["Accept"] = "application/json"
	//header["content-md5"] = dataMd5         //这不是必须的参数
	header["Content-Type"] = `application/json`
	header["x-ca-key"] = AppKey
	header["x-ca-timestamp"] = timestamp
	//header["x-ca-timestamp"] = "1675865396690"
	//header["x-ca-nonce"] = "fc5c0772-b5b4-46f7-a68d-f563ab4864c0"
	header["x-ca-signature-Headers"] = `x-ca-key,x-ca-timestamp`
	sign := HKGetSign(header, uri)
	//fmt.Println("-->> header>", header)
	//fmt.Println("-->> post sign>", sign)
	for ks, vv := range header {
		request.Header.Add(ks, vv)
	}
	header["x-ca-signature"] = sign
	//headerStr, _ := json.Marshal(header)
	//zlog.GetLogger().Debugf(string(headerStr))
	request.Header.Add("x-ca-signature", sign)
	resp, err := client.Do(request)
	if err != nil {
		//zlog.GetLogger().Error("Artemis http请求错误:", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	defer client.CloseIdleConnections()
	return body, err
}

func Get(uri string, params map[string]interface{}) (body []byte, err error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}}
	query := GetQuerys(params, false)
	// 获取 request请求
	request, err := http.NewRequest("GET", path+uri+"?"+query, nil)

	if err != nil {
		//zlog.GetLogger().Error("Post Request Error:", err)
		return nil, nil
	}

	// 加入 token
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json;charset=UTF-8")
	resp, err := client.Do(request)
	if err != nil {
		//zlog.GetLogger().Error("Post Response Error:", err)
		return nil, nil
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	defer client.CloseIdleConnections()
	return body, nil
}

func GetQuerys(body interface{}, goSort bool) string {
	keys := []string{}
	k2i := map[string]int{}
	structs := reflect.TypeOf(body)
	count := structs.NumField()
	for i := 0; i < count; i++ {
		locField := structs.Field(i)
		t := locField.Tag
		k2i[t.Get("json")] = i
		keys = append(keys, t.Get("json"))
	}
	if goSort {
		sort.Strings(keys)
	}
	values := []string{}
	vlist := reflect.ValueOf(body)
	for _, k := range keys {
		values = append(values, k+"="+vlist.Field(k2i[k]).String())
	}
	httpQuery := strings.Join(values, "&")
	return httpQuery
}

func HKGetSign(header map[string]string, uri string) string {
	signStr := HKGetSignStr(header, uri)
	key := []byte(AppSecret)
	h := hmac.New(sha256.New, key)
	//message, _ := json.Marshal(body)
	//println(string(message))
	h.Write([]byte(signStr))
	//sha := hex.EncodeToString(h.Sum(nil))    //坑啊，在PHP中 hash 计算后是直接用字节去base64编码的，但是网上GO的例子都是直接用hex.EncodeToString
	sha := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return sha
}

func HKGetSignStr(data map[string]string, uri string) string {
	next := `
`
	str := `POST` + next + data["Accept"] + next
	if _, ok1 := data["content-md5"]; ok1 {
		str += data["content-md5"] + next
	}
	str += data["Content-Type"] + next
	str += `x-ca-key:` + AppKey + next
	if _, ok := data["x-ca-nonce"]; ok {
		str += `x-ca-nonce:` + data["x-ca-nonce"] + next
	}
	str += `x-ca-timestamp:` + data["x-ca-timestamp"] + next
	str += "/artemis" + uri
	return str
}
