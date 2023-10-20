package judger

import (
	"encoding/json"
	"net/http"
)

type Resp struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Result  any    `json:"result,omitempty"`
}

func NewResp(result any, err error) Resp {
	if err != nil {
		return NewErrResp(err.Error())
	} else {
		return NewOkResp(result)
	}
}
func NewErrResp(err string) Resp {
	return Resp{
		Success: false,
		Error:   err,
	}
}
func NewOkResp(result any) Resp {
	return Resp{
		Success: true,
		Result:  result,
	}
}

func UnmarshalResp(jsonBytes []byte) (resp Resp) {
	_ = json.Unmarshal(jsonBytes, &resp)
	return
}

func (resp Resp) ToJSON() []byte {
	bytes, _ := json.Marshal(resp)
	return bytes
}

func (resp Resp) WriteTo(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "origin, content-type, accept")

	bytes, _ := json.Marshal(resp)
	_, _ = w.Write(bytes)
}
