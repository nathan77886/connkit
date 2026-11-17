package operations

import (
	"github.com/nathan77886/connkit/internal/store"
	"net/url"
	"strings"
	"testing"
)

func TestAliyunRPCSDKSignatureVector(t *testing.T) {
	// Published test vectors from aliyun/alibaba-cloud-sdk-go/sdk/auth/rpc_signature_composer_test.go.
	q := url.Values{"AccessKeyId": {"accessKeyId"}, "Version": {""}, "Action": {""}, "Format": {"JSON"}, "Timestamp": {"mock date"}, "SignatureMethod": {"HMAC-SHA1"}, "SignatureVersion": {"1.0"}, "SignatureType": {""}, "SignatureNonce": {"MOCK_UUID"}, "RegionId": {"regionId"}}
	if got := aliyunRPCSignature(q, "accessKeySecret", "GET"); got != "7loPmFjvDnzOVnQeQNj85S6nFGY=" {
		t.Fatalf("SDK AK signature mismatch: %s", got)
	}
	q.Set("SecurityToken", "accessKeyStsToken")
	if got := aliyunRPCSignature(q, "accessKeySecret", "GET"); got != "5Nxdcler+ihqWqv0Hr2On4PsBf4=" {
		t.Fatalf("SDK STS signature mismatch: %s", got)
	}
}

func TestAliyunRPCOriginAndCredentialBoundary(t *testing.T) {
	cfg := AliyunRPCSettings{Service: "ecs", RegionID: "cn-shanghai", AccessKeyID: "test-id", AccessKeySecret: "test-secret"}
	tests := []struct{ name, path string }{
		{"missing action", "?InstanceId=x"},
		{"duplicate action", "?Action=DescribeInstances&Action=DeleteInstance"}, {"duplicate param", "?Action=DescribeInstances&InstanceId=a&InstanceId=b"},
		{"region override", "?Action=DescribeInstances&RegionId=other"}, {"signature injection", "?Action=DescribeInstances&Signature=x"},
		{"version override", "?Action=DescribeInstances&Version=x"}, {"token override", "?Action=DescribeInstances&SecurityToken=x"},
		{"bad escape", "?Action=DescribeInstances&X=%xx"}, {"subpath", "/other?Action=DescribeInstances"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("https://ecs.cn-shanghai.aliyuncs.com/" + strings.TrimPrefix(tt.path, "/"))
			if err := signAliyunRPC(u, cfg, "GET"); err == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
	for _, host := range []string{"https://evil.test/", "http://ecs.cn-shanghai.aliyuncs.com/", "https://ecs.cn-shanghai.aliyuncs.com:443/", "https://ecs.cn-beijing.aliyuncs.com/"} {
		u, _ := url.Parse(host + "?Action=DescribeInstances")
		if err := signAliyunRPC(u, cfg, "GET"); err == nil {
			t.Fatal("unsafe origin accepted:", host)
		}
	}
	u, _ := url.Parse("https://ecs.cn-shanghai.aliyuncs.com/?Action=DescribeInstances&InstanceIds=%5B%22i-test%22%5D")
	if err := signAliyunRPC(u, cfg, "GET"); err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("RegionId") != "cn-shanghai" || q.Get("Signature") == "" || q.Get("InstanceIds") != `["i-test"]` {
		t.Fatal("missing signed parameters")
	}
	signature := q.Get("Signature")
	q.Del("Signature")
	if signature != aliyunRPCSignature(q, cfg.AccessKeySecret, "GET") {
		t.Fatal("invalid request signature")
	}
	other, _ := url.Parse("https://ecs.cn-shanghai.aliyuncs.com/?Action=DescribeInstances")
	if err := signAliyunRPC(other, cfg, "GET"); err != nil {
		t.Fatal(err)
	}
	if other.Query().Get("SignatureNonce") == q.Get("SignatureNonce") {
		t.Fatal("reused nonce")
	}
}

func TestAliyunRPCRejectsUnsignedBodyAndUnsupportedMethod(t *testing.T) {
	s := &Service{}
	cfg := Settings{BaseURL: "https://ecs.cn-shanghai.aliyuncs.com", AliyunRPC: &AliyunRPCSettings{Service: "ecs", RegionID: "cn-shanghai", AccessKeyID: "test", AccessKeySecret: "secret"}}
	for _, in := range []Input{{Method: "DELETE", Path: "?Action=DeleteInstance"}, {Method: "GET", Body: "Action=DeleteInstance", Path: "?Action=DescribeInstances"}} {
		if _, err := s.http(t.Context(), store.Connection{Type: "https"}, cfg, "https_request", in); err == nil || !strings.Contains(err.Error(), "RPC") {
			t.Fatalf("unsafe method/body accepted: %v", err)
		}
	}
}

func TestAliyunRPCSignsRequestedActionsAndMethod(t *testing.T) {
	cfg := AliyunRPCSettings{Service: "ecs", RegionID: "cn-shanghai", AccessKeyID: "test", AccessKeySecret: "fixture"}
	for _, action := range []string{"DescribeInstances", "DeleteInstance", "RunCommand"} {
		for _, method := range []string{"GET", "POST"} {
			u, _ := url.Parse("https://ecs.cn-shanghai.aliyuncs.com/?Action=" + action)
			if err := signAliyunRPC(u, cfg, method); err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			got := q.Get("Signature")
			q.Del("Signature")
			if got != aliyunRPCSignature(q, cfg.AccessKeySecret, method) {
				t.Fatal("signature method mismatch")
			}
		}
	}
}
