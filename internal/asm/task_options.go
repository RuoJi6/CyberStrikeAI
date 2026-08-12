package asm

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

func taskOptionAllowed(keys ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}

func rejectUnknownTaskOptions(provider string, options map[string]interface{}, allowed map[string]struct{}) error {
	unknown := make([]string, 0)
	for key := range options {
		if _, ok := allowed[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s 不支持的任务选项: %s", provider, strings.Join(unknown, ", "))
}

func taskOptionString(provider string, options map[string]interface{}, key, fallback string, maxLength int) (string, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return fallback, nil
	}
	result, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s 任务选项 %s 必须是字符串", provider, key)
	}
	result = strings.TrimSpace(result)
	if maxLength > 0 && len(result) > maxLength {
		return "", fmt.Errorf("%s 任务选项 %s 不能超过 %d 字符", provider, key, maxLength)
	}
	return result, nil
}

func taskOptionBool(provider string, options map[string]interface{}, key string, fallback bool) (bool, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return fallback, nil
	}
	result, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("%s 任务选项 %s 必须是布尔值", provider, key)
	}
	return result, nil
}

func taskOptionInt(provider string, options map[string]interface{}, key string, fallback, minimum, maximum int) (int, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return fallback, nil
	}
	var result int64
	switch number := value.(type) {
	case int:
		result = int64(number)
	case int32:
		result = int64(number)
	case int64:
		result = number
	case float64:
		if math.Trunc(number) != number {
			return 0, fmt.Errorf("%s 任务选项 %s 必须是整数", provider, key)
		}
		result = int64(number)
	case json.Number:
		parsed, err := strconv.ParseInt(number.String(), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s 任务选项 %s 必须是整数", provider, key)
		}
		result = parsed
	default:
		return 0, fmt.Errorf("%s 任务选项 %s 必须是整数", provider, key)
	}
	if result < int64(minimum) || result > int64(maximum) {
		return 0, fmt.Errorf("%s 任务选项 %s 必须在 %d 到 %d 之间", provider, key, minimum, maximum)
	}
	return int(result), nil
}

func taskOptionEnum(provider string, options map[string]interface{}, key, fallback string, allowed ...string) (string, error) {
	value, err := taskOptionString(provider, options, key, fallback, 200)
	if err != nil {
		return "", err
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s 任务选项 %s 仅支持: %s", provider, key, strings.Join(allowed, ", "))
}

func taskOptionStringSlice(provider string, options map[string]interface{}, key string, fallback []string, maximumItems, maxItemLength int) ([]string, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return append([]string(nil), fallback...), nil
	}
	var raw []interface{}
	switch items := value.(type) {
	case []interface{}:
		raw = items
	case []string:
		raw = make([]interface{}, 0, len(items))
		for _, item := range items {
			raw = append(raw, item)
		}
	default:
		return nil, fmt.Errorf("%s 任务选项 %s 必须是字符串数组", provider, key)
	}
	if maximumItems > 0 && len(raw) > maximumItems {
		return nil, fmt.Errorf("%s 任务选项 %s 最多包含 %d 项", provider, key, maximumItems)
	}
	result := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s 任务选项 %s 必须是字符串数组", provider, key)
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, fmt.Errorf("%s 任务选项 %s 不能包含空值", provider, key)
		}
		if maxItemLength > 0 && len(text) > maxItemLength {
			return nil, fmt.Errorf("%s 任务选项 %s 的单项不能超过 %d 字符", provider, key, maxItemLength)
		}
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		result = append(result, text)
	}
	return result, nil
}

func taskOptionIntSlice(provider string, options map[string]interface{}, key string, maximumItems int) ([]int, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.([]interface{})
	if !ok {
		if typed, typedOK := value.([]int); typedOK {
			items = make([]interface{}, 0, len(typed))
			for _, item := range typed {
				items = append(items, item)
			}
		} else {
			return nil, fmt.Errorf("%s 任务选项 %s 必须是整数数组", provider, key)
		}
	}
	if maximumItems > 0 && len(items) > maximumItems {
		return nil, fmt.Errorf("%s 任务选项 %s 最多包含 %d 项", provider, key, maximumItems)
	}
	result := make([]int, 0, len(items))
	seen := make(map[int]struct{}, len(items))
	for _, item := range items {
		value, err := taskOptionInt(provider, map[string]interface{}{key: item}, key, 0, 1, math.MaxInt32)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func optionStringIn(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
