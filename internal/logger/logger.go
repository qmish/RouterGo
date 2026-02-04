package logger

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level string
}

func New(level string) *Logger {
	if level == "" {
		level = "info"
	}
	return &Logger{
		out:   os.Stdout,
		level: level,
	}
}

func (l *Logger) Debug(msg string, fields map[string]any) {
	l.log("debug", msg, fields)
}

func (l *Logger) Info(msg string, fields map[string]any) {
	l.log("info", msg, fields)
}

func (l *Logger) Warn(msg string, fields map[string]any) {
	l.log("warn", msg, fields)
}

func (l *Logger) Error(msg string, fields map[string]any) {
	l.log("error", msg, fields)
}

func (l *Logger) log(level string, msg string, fields map[string]any) {
	if !shouldLog(level, l.level) {
		return
	}

	entry := map[string]any{
		"ts":    time.Now().Format(time.RFC3339),
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(b, '\n'))
}

func shouldLog(level string, current string) bool {
	order := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
	}
	return order[level] >= order[current]
}
