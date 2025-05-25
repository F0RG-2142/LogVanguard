package logger

import (
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
)

func NewLogger() *zap.Logger {
    config := zap.NewProductionConfig()
    config.EncoderConfig = zapcore.EncoderConfig{
        TimeKey:        "ts",
        LevelKey:       "level",
        NameKey:        "logger",
        CallerKey:      "caller",
        FunctionKey:    zapcore.OmitKey,
        StacktraceKey:  "stacktrace",
        LineEnding:     "\n",
        EncodeLevel:    zapcore.CapitalColorLevelEncoder,
        EncodeTime:     zapcore.ISO8601TimeEncoder,
        EncodeDuration: zapcore.StringDurationEncoder,
        EncodeCaller:   zapcore.ShortCallerEncoder,
    }

    config.Level.SetLevel(zap.InfoLevel)
    config.OutputPaths = []string{"stdout"}

    logger, _ := config.Build()
    return logger
}