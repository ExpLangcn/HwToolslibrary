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
			Name:     "通达OA v2017 任意文件上传漏洞",
			Author:   "ExpLang",
			Describe: "通达OA v2017 action_upload.php 文件过滤不足且无需后台权限，导致任意文件上传漏洞\n\n#",
			Date:     "2023-09-26",
			Tags:     []string{"通达OA", "TongdaOA", "Download File"},
			Level:    "high",
			Link:     []string{"https://peiqi.h-k.pw/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v2017%20action_upload.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html"},
		},
		Other: info.OtherInfo{
			FOFAGrammar:  "app=\"TDXK-通达OA\"",
			QuakeGrammar: "",
		},
	}
}
