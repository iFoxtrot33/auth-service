package req

import (
	"encoding/json"
	"errors"
	"io"
)

func Decode[T any](body io.ReadCloser) (T, error) {
	var payload T
	err := json.NewDecoder(body).Decode(&payload)

	if body == nil {
		return payload, errors.New("request body is nil")
	}

	if err != nil {
		return payload, err
	}
	return payload, nil
}
