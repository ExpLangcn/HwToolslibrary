# HwToolslibrary
## 示例
```Golang

package main

import(
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
	"github.com/ExpLangcn/HwToolslibrary/library/info"
	"github.com/ExpLangcn/HwToolslibrary/library/utils"	
)

var POC info.POC

func init() {
    POC = info.POC{ // 初始化POC信息
    Info: info.POCInfo{ // 定义POC 漏洞信息
        Name:     "POC 名称",
        Author:   "POC 作者",
        Describe: "POC 漏洞介绍",
        Date:     "POC 发布时间",
        Tags:     []string{"标签1", "标签2", "..."}, // POC 标签
        Level:    "风险等级", // Low, medium, high
        Link:     []string{"http://xxx.com", "https://www.xxx.com"}, // POC 漏洞参考链接
    },
    Other: info.OtherInfo{
        FOFAGrammar:  "body=\"HwToolsPro test\"", // POC 漏洞 FOFA 搜索语法
        QuakeGrammar: "body: \"HwToolsPro test\"", // POC 漏洞 Quake 搜索语法
        }, 
    }
}

func Start(Target string, ProxyURL string) (bool, error) { // 调用试例 必须带有"Target string, ProxyURL string" 参数，且类型一致，返回类型必须为bool, error
    Httprecord := make(map[*httpclient.RequestOptions]*httpclient.Response) // 生成存储请求信息的map
	
	requestOption := &httpclient.RequestOptions{ // 配置请求信息
		Method:      http.MethodGet, 
		URL:         Target,
		Path:        filebody, 
		Headers:     map[string]string{"User-Agent": httpclient.RandomUserAgent()}, // 使用库中的httpclient.RandomUserAgent()函数生成随机UserAgent 
		Cookies:     []*http.Cookie{{Name: "session", Value: "abc123"}}, 
		ProxyURL:    ProxyURL, 
		RequestBody: []byte(""), // 因为是 Get 方式，所以为空
    }

    responseOption, success := httpclient.SendRequest(*requestOption) // 发送请求
    Httprecord[requestOption] = responseOption // 将请求信息存入map

    if responseOption.Err != nil {
		return false, responseOption.Err
	} else {
		if !success {
            // 发送请求失败
            return false, errors.New("请求失败")
        } else if responseOption.StatusCode == 200 { // 判断状态码
            return true, nil // 返回漏洞存在的结果
        }
    }

    POC.Info.HttpInfo = Httprecord // 将请求信息存入POC结构体中 
	return false, errors.New("漏洞不存在")
}
```

## 使用 AI 自动生成POC 插件
* 打开类似于 ChatGPT 的对话框，将库内的所有.go后缀的文件内容逐个发给 GPT。
* 当全部发送后将你需要生成的 POC 漏洞信息发送给 GPT 并在结尾说明判断漏洞存在的逻辑即可。

**注意：建议参考网络上大部分漏洞文库的格式来生成 POC，也可直接发送请求包并告知如何判断漏洞存在即可。**

## 联系

* 博客站点：[阿浪的小破站](https://www.yunjianxx.com/)
* Bilibili：[不懂安全的阿浪](https://space.bilibili.com/3546377619508015)
* Twitter：[@ExpLang_Cn](https://twitter.com/ExpLang_Cn)