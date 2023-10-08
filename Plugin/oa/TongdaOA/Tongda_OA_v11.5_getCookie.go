package main

import (
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
	"github.com/ExpLangcn/HwToolslibrary/library/info"
)

var POC info.POC
var Httprecord = make(map[*httpclient.RequestOptions]*httpclient.Response) // 配置请求信息

func init() {
	POC = info.POC{ // 初始化POC信息
		Info: info.POCInfo{
			Name:     "",
			Author:   "ExpLang",
			Describe: "",
			Date:     "2023-10-08",
			Tags:     []string{"", ""},
			Level:    "high",
			Link:     []string{""},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "",
			QuakeGrammar: "",
		},
	}
}
