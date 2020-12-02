package wechat

import (
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// VerifyHandler implements https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html
// When you are testing with Wechat 公眾平台測試號, you need to verify your server.
type VerifyHandler struct {
	Token string
}

func (h *VerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	signature := q.Get("signature")
	timestamp := q.Get("timestamp")
	nonce := q.Get("nonce")
	echostr := q.Get("echostr")

	arr := []string{h.Token, timestamp, nonce}
	sort.Strings(arr)

	concatenated := strings.Join(arr, "")

	hash := sha1.New()
	hash.Write([]byte(concatenated))
	sum := hash.Sum(nil)

	actual := fmt.Sprintf("%x", sum)

	if subtle.ConstantTimeCompare([]byte(signature), []byte(actual)) == 1 {
		w.Write([]byte(echostr))
	}
}
