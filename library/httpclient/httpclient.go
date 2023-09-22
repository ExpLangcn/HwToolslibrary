package httpclient

import (
	"bytes"
	"net/http"
	"net/url"
)

// RequestOptions 包含自定义请求选项的结构
type RequestOptions struct {
	Method      string            // 请求方式
	URL         string            // 请求 url 地址
	Path        string            // 请求路径
	Headers     map[string]string //请求头
	Cookies     []*http.Cookie    // 请求 cookie
	ProxyURL    string            // 代理配置
	RequestBody []byte            // 请求包
}

// Response 包含响应信息的结构
type Response struct {
	StatusCode int         // 响应状态码
	Body       []byte      // 响应包
	Header     http.Header //响应头
	Err        error       // 响应错误
}

// SendRequest 发送 HTTP 请求，并返回 Response 结构
func SendRequest(options RequestOptions) (*Response, bool) {
	client := &http.Client{}
	reqURL, err := url.Parse(options.URL + options.Path)
	if err != nil {
		return &Response{Err: err}, false
	}

	req, err := http.NewRequest(options.Method, reqURL.String(), bytes.NewBuffer(options.RequestBody))
	if err != nil {
		return &Response{Err: err}, false
	}

	// 设置请求头
	for key, value := range options.Headers {
		req.Header.Set(key, value)
	}

	// 设置 Cookie
	for _, cookie := range options.Cookies {
		req.AddCookie(cookie)
	}

	// 设置代理
	if options.ProxyURL != "" {
		proxyURL, err := url.Parse(options.ProxyURL)
		if err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return &Response{Err: err}, false
	}
	defer resp.Body.Close()

	response := &Response{
		StatusCode: resp.StatusCode,
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		response.Err = err
		return response, false
	}

	response.Body = buf.Bytes()
	response.Header = resp.Header

	return response, true
}
