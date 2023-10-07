package info

import (
	"github.com/ExpLangcn/HwToolslibrary/library/httpclient"
)

type POC struct {
	Info  POCInfo   // POC信息,POCInfo类型
	Other OtherInfo // POC其他信息,OtherInfo
}

type POCInfo struct {
	Name     string                                              // POC名称,字符串类型
	Author   string                                              // POC作者,字符串类型
	Describe string                                              // POC描述信息,字符串类型
	Date     string                                              // 编写时间,字符串类型
	Tags     []string                                            // 漏洞标签,字符串数组类型
	Level    string                                              // POC等级,字符串类型
	Link     []string                                            // POC相关链接,字符串数组类型
	HttpInfo map[*httpclient.RequestOptions]*httpclient.Response // Http信息,HttpInfo类型
}

type OtherInfo struct {
	FOFAGrammar  string // FOFA配置信息,字符串类型
	QuakeGrammar string // Quake配置信息,字符串类型
}
