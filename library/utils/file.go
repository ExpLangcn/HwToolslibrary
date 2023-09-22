package utils

import (
	"bufio"
	"os"
)

// ReadFileLines函数是逐行读取文件内容的函数，需要提供文件相对路径或绝对路径，返回一个数组和报错信息
func ReadFileLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Check for errors during scanning.
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
