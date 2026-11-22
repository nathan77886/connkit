// Package files stages uploads in private S3-compatible storage for target-side downloads.
package files

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// Config configures one S3-compatible staging bucket. Credentials are encrypted at rest.
type Config struct {
	ClearSessionToken bool   `json:"clear_session_token,omitempty"`
	Enabled           bool   `json:"enabled"`
	Endpoint          string `json:"endpoint"`
	Region            string `json:"region"`
	Bucket            string `json:"bucket"`
	AccessKey         string `json:"access_key"`
	SecretKey         string `json:"secret_key"`
	SessionToken      string `json:"session_token"`
	Prefix            string `json:"prefix"`
	ForcePathStyle    bool   `json:"force_path_style"`
	AllowHTTP         bool   `json:"allow_http"`
	ProxyID           *uint  `json:"proxy_id"`
	MaxFileSizeMB     int64  `json:"max_file_size_mb"`
}

// Normalize validates an explicitly configured endpoint; no ambient AWS credentials are used.
func (c *Config) Normalize() error {
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.Prefix == "" {
		c.Prefix = "connkit"
	}
	c.Prefix = strings.Trim(c.Prefix, "/")
	if c.MaxFileSizeMB == 0 {
		c.MaxFileSizeMB = 512
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && (u.Scheme != "http" || !c.AllowHTTP)) {
		return errors.New("valid HTTPS S3 endpoint required; HTTP must be explicitly enabled")
	}
	if c.Bucket == "" || strings.ContainsAny(c.Bucket, "/\\\r\n") || c.AccessKey == "" || c.SecretKey == "" {
		return errors.New("bucket and S3 credentials required")
	}
	if c.Prefix == "" || path.Clean(c.Prefix) != c.Prefix || strings.HasPrefix(c.Prefix, "..") || strings.ContainsAny(c.Prefix, "\\\r\n\x00") {
		return errors.New("invalid object prefix")
	}
	if c.MaxFileSizeMB < 1 || c.MaxFileSizeMB > 5120 {
		return errors.New("maximum file size must be 1–5120 MiB")
	}
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	return nil
}

// UploadGrant is a temporary authorization for one object, without storage credentials.
type UploadGrant struct {
	URL       string      `json:"url"`
	Method    string      `json:"method"`
	Headers   http.Header `json:"headers"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// Cloud is the storage boundary used by the transfer service.
type Cloud interface {
	SignPut(context.Context, string, int64) (UploadGrant, error)
	Size(context.Context, string) (int64, error)
	SignGet(context.Context, string) (string, error)
	Delete(context.Context, string) error
}

type s3Cloud struct {
	client *s3.Client
	bucket string
}

type archiveUploader interface {
	Upload(context.Context, string, io.Reader, int64) error
}

func newCloud(_ context.Context, s *store.Store, c Config) (Cloud, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (netConn net.Conn, err error) {
		return (&route.Dialer{Store: s}).DialContext(ctx, c.ProxyID, address)
	}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableKeepAlives: true}
	client := s3.NewFromConfig(aws.Config{Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, c.SessionToken), HTTPClient: &http.Client{Transport: transport, Timeout: 45 * time.Second}, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(c.Endpoint)
		o.UsePathStyle = c.ForcePathStyle
		o.RetryMaxAttempts = 1
	})
	return &s3Cloud{client: client, bucket: c.Bucket}, nil
}
func (c *s3Cloud) SignPut(ctx context.Context, key string, size int64) (UploadGrant, error) {
	if size <= 0 {
		return UploadGrant{}, errors.New("upload size must be positive")
	}
	ttl := 15 * time.Minute
	result, err := s3.NewPresignClient(c.client).PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), ContentLength: aws.Int64(size), ContentType: aws.String("application/octet-stream")}, func(o *s3.PresignOptions) { o.Expires = ttl })
	if err != nil {
		return UploadGrant{}, errors.New("cloud upload signing failed")
	}
	headers := result.SignedHeader.Clone()
	headers.Del("Host")
	return UploadGrant{URL: result.URL, Method: result.Method, Headers: headers, ExpiresAt: time.Now().Add(ttl)}, nil
}
func (c *s3Cloud) Upload(ctx context.Context, key string, body io.Reader, size int64) error {
	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), Body: body, ContentLength: aws.Int64(size), ContentType: aws.String("application/octet-stream")})
	if err != nil {
		return errors.New("cloud archive object upload failed")
	}
	return nil
}
func (c *s3Cloud) Size(ctx context.Context, key string) (int64, error) {
	result, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		return 0, errors.New("uploaded cloud object unavailable")
	}
	return aws.ToInt64(result.ContentLength), nil
}
func (c *s3Cloud) SignGet(ctx context.Context, key string) (string, error) {
	result, err := s3.NewPresignClient(c.client).PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)}, func(o *s3.PresignOptions) { o.Expires = 5 * time.Minute })
	if err != nil {
		return "", errors.New("cloud download signing failed")
	}
	return result.URL, nil
}
func (c *s3Cloud) Delete(ctx context.Context, key string) error {
	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		return errors.New("cloud object cleanup failed")
	}
	return nil
}
