//go:build !windows

package libraryflow

import (
	"reflect"
	"time"
)

func fileChangeTimeUnixNano(_ string, sys any) int64 {
	value := reflect.ValueOf(sys)
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0
	}
	for _, name := range []string{"Ctim", "Ctimespec"} {
		field := value.FieldByName(name)
		if !field.IsValid() || field.Kind() != reflect.Struct {
			continue
		}
		seconds := field.FieldByName("Sec")
		nanos := field.FieldByName("Nsec")
		if seconds.IsValid() && nanos.IsValid() && seconds.CanInt() && nanos.CanInt() {
			return seconds.Int()*int64(time.Second) + nanos.Int()
		}
	}
	return 0
}
