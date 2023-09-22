package httpclient

import (
	"math/rand"
	"time"
)

// 预定义的 User-Agent 列表
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15",
	// 添加更多 User-Agent 到列表中
}

// 随机生成一个 User-Agent
func RandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	index := rand.Intn(len(userAgents))
	return userAgents[index]
}
