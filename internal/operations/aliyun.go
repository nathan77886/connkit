package operations

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // Alibaba Cloud RPC signature version 1.0 requires HMAC-SHA1.
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

// AliyunRPCSettings are encrypted with the HTTPS connection, never supplied by a tool caller.
type AliyunRPCSettings struct {
	Service         string `json:"service"`
	RegionID        string `json:"region_id"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	SecurityToken   string `json:"security_token,omitempty"`
}

var aliyunReadActions = map[string][]string{
	"ecs": {"DescribeRegions", "DescribeInstances", "DescribeInstanceAttribute", "DescribeCloudAssistantStatus", "DescribeCloudAssistantSettings", "DescribeInvocations", "DescribeInvocationResults", "DescribeSecurityGroups", "DescribeSecurityGroupAttribute", "DescribeNetworkInterfaces", "DescribeDisks", "DescribeInstanceHistoryEvents", "DescribeInstanceMaintenanceAttributes"},
	"vpc": {"DescribeRegions", "DescribeVpcs", "DescribeVpcAttribute", "DescribeVSwitches", "DescribeRouteTables", "DescribeRouteEntryList", "DescribeNatGateways", "DescribeSnatTableEntries", "DescribeNetworkAcls"},
	"hbr": {"DescribeVaults", "DescribeClients", "DescribeClientsV2", "DescribeBackupJobs", "DescribeBackupJobs2", "DescribeBackupPlans", "DescribeBackupPlans2", "DescribeSnapshots"},
}

func signAliyunRPC(u *url.URL, cfg AliyunRPCSettings) error {
	versions := map[string]string{"ecs": "2014-05-26", "vpc": "2016-04-28", "hbr": "2017-09-08"}
	version, ok := versions[cfg.Service]
	if !ok || cfg.RegionID == "" || strings.ContainsAny(cfg.RegionID, "/.:?#\\") || cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" {
		return errors.New("Aliyun RPC requires a supported service, region and access key")
	}
	host := cfg.Service + "." + cfg.RegionID + ".aliyuncs.com"
	if u.Scheme != "https" || u.Host != host || u.Path != "/" || u.User != nil || u.Fragment != "" {
		return errors.New("Aliyun RPC requires the configured service regional HTTPS root endpoint")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("invalid Aliyun RPC query")
	}
	for _, values := range q {
		if len(values) != 1 {
			return errors.New("duplicate Aliyun RPC parameter")
		}
	}
	if !slices.Contains(aliyunReadActions[cfg.Service], q.Get("Action")) {
		return errors.New("Aliyun RPC action is not in the read-only allowlist")
	}
	for _, key := range []string{"AccessKeyId", "Signature", "SignatureMethod", "SignatureVersion", "SignatureNonce", "SignatureType", "SecurityToken", "BearerToken", "Timestamp", "Format", "Version", "RegionId"} {
		if q.Has(key) {
			return errors.New("Aliyun RPC authentication, version and region parameters are connection-managed")
		}
	}
	q.Set("AccessKeyId", cfg.AccessKeyID)
	q.Set("Version", version)
	q.Set("RegionId", cfg.RegionID)
	q.Set("Format", "JSON")
	q.Set("SignatureMethod", "HMAC-SHA1")
	q.Set("SignatureVersion", "1.0")
	q.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	q.Set("SignatureNonce", hex.EncodeToString(nonce))
	if cfg.SecurityToken != "" {
		q.Set("SecurityToken", cfg.SecurityToken)
	}
	q.Set("Signature", aliyunRPCSignature(q, cfg.AccessKeySecret))
	u.RawQuery = q.Encode()
	return nil
}

// Canonicalization follows Alibaba Cloud's RPC v1 SDK; spaces use %20, not +.
func aliyunRPCSignature(q url.Values, secret string) string {
	canonical := strings.ReplaceAll(q.Encode(), "+", "%20")
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte("GET&%2F&" + url.QueryEscape(canonical)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
