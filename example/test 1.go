package example

import (
	"errors"
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
	"github.com/ExpLangcn/HwToolslibrary/library/info"
	"github.com/ExpLangcn/HwToolslibrary/library/utils"
	"net/http"
)

var POC info.POC

func init() {
	POC = info.POC{ // 初始化POC信息
		Info: info.POCInfo{
			Name:     "测试漏洞1",
			Author:   "ExpLang",
			Describe: "用于测试HwToolsPro工具的插件使用",
			Date:     "2023-09-04",
			Tags:     []string{"Test", "Demo", "SQLI"},
			Level:    "high",
			Link:     []string{"http://xxx.com", "https://www.xxx.com"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "body=\"HwToolsPro test\"",
			QuakeGrammar: "body: \"HwToolsPro test\"",
		},
	}
}

func Start(Target string, ProxyURL string) (bool, error) { // 调用试例

	FileBodyList, err := utils.ReadFileLines("plus/test/test.txt") // 假如是未授权漏洞,读取多个路径
	if err != nil {
		return false, errors.New("读取请求路径文件错误!") // 因为还没有进行发送请求的操作，所以返回漏洞信息并不包含 HTTP请求信息
	}

	Httprecord := make(map[*httpclient.RequestOptions]*httpclient.Response) // 配置请求信息
	for _, filebody := range FileBodyList {
		requestOption := &httpclient.RequestOptions{
			Method:  http.MethodGet,
			URL:     Target,
			Path:    filebody,
			Headers: map[string]string{"User-Agent": httpclient.RandomUserAgent()},
			//Cookies:     []*http.Cookie{{Name: "session", Value: "abc123"}},
			ProxyURL:    ProxyURL,
			RequestBody: []byte(""), // 因为是 Get 方式，所以为空
		}

		responseOption, success := httpclient.SendRequest(*requestOption)
		Httprecord[requestOption] = responseOption

		if responseOption.Err != nil {
			// 处理错误
			return false, responseOption.Err
		} else if responseOption.StatusCode == 200 {
			if !success {
				// 发送请求失败
				return false, errors.New("请求失败")
			}
		}
	}

	POC.Info.HttpInfo = Httprecord

	for requestOption, responseOption := range Httprecord { // 漏洞判定逻辑
		if responseOption.StatusCode == 404 { // 如果等于 404 并且路径是 1233就漏洞存在
			if requestOption.Path == "1233" {
				return true, nil
			} else {
				continue
			}
		}
	}

	return false, errors.New("漏洞不存在")
}
