package operations

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

type mongoDialer struct {
	s         *store.Store
	proxyID   *uint
	operation context.Context
}

func (d mongoDialer) DialContext(ctx context.Context, _ string, addr string) (net.Conn, error) {
	return (&route.Dialer{Store: d.s}).DialForOperation(d.operation, ctx, d.proxyID, addr)
}

func (s *Service) mongo(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	if cfg.Database == "" {
		return nil, errors.New("MongoDB database required")
	}
	if !strings.HasPrefix(cfg.URI, "mongodb://") {
		return nil, errors.New("mongodb:// URI required; SRV discovery is unavailable")
	}
	u, err := url.Parse(cfg.URI)
	if err != nil || u.Scheme != "mongodb" || u.Host == "" {
		return nil, errors.New("invalid MongoDB URI")
	}
	// These native-driver options cannot be bypassed by URI parameters.
	q := u.Query()
	for k, vs := range q {
		key := strings.ToLower(k)
		if key == "tlsinsecure" || key == "tlsallowinvalidcertificates" || key == "tlsallowinvalidhostnames" {
			for _, v := range vs {
				if v != "false" {
					return nil, errors.New("insecure MongoDB TLS is forbidden")
				}
			}
		}
	}
	opts := options.Client().ApplyURI(cfg.URI).SetDialer(mongoDialer{s.Store, c.ProxyID, ctx}).SetMaxPoolSize(1).SetRetryReads(false).SetRetryWrites(false)
	if cfg.Username != "" {
		opts.SetAuth(options.Credential{Username: cfg.Username, Password: cfg.Password, AuthSource: cfg.Database})
	}
	if cfg.TLS {
		tc, err := tlsConfig(cfg, "")
		if err != nil {
			return nil, err
		}
		opts.SetTLSConfig(tc)
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, errors.New("invalid MongoDB configuration")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(cleanup)
	}()
	db := client.Database(cfg.Database)
	if tool == "mongo_test" {
		if client.Ping(ctx, readpref.Primary()) != nil {
			return nil, errors.New("MongoDB authentication/ping failed")
		}
		return map[string]any{"ok": true, "stage": "authenticated"}, nil
	}
	if tool == "mongo_collections" {
		names, err := db.ListCollectionNames(ctx, bson.D{})
		if err != nil {
			return nil, errors.New("MongoDB collection discovery failed")
		}
		return map[string]any{"collections": names}, nil
	}
	if in.Collection == "" {
		return nil, errors.New("collection required")
	}
	filter := bson.D{}
	if in.Filter != "" {
		if bson.UnmarshalExtJSON([]byte(in.Filter), false, &filter) != nil {
			return nil, errors.New("invalid Extended JSON filter")
		}
	}
	collection := db.Collection(in.Collection)
	var cursor *mongo.Cursor
	switch tool {
	case "mongo_find":
		cursor, err = collection.Find(ctx, filter, options.Find().SetLimit(int64(in.Limit)))
	case "mongo_count":
		n, err := collection.CountDocuments(ctx, filter)
		if err != nil {
			return nil, errors.New("MongoDB count failed")
		}
		return map[string]any{"count": n}, nil
	case "mongo_aggregate":
		var pipeline mongo.Pipeline
		if bson.UnmarshalExtJSON([]byte(in.Pipeline), false, &pipeline) != nil {
			return nil, errors.New("invalid Extended JSON pipeline")
		}
		// Recursively reject writing stages, including stages inside nested pipelines.
		if writesPipeline(pipeline) {
			return nil, errors.New("aggregation write stages are unavailable")
		}
		pipeline = append(pipeline, bson.D{{Key: "$limit", Value: in.Limit}})
		cursor, err = collection.Aggregate(ctx, pipeline)
	case "mongo_insert", "mongo_update", "mongo_delete":
		if !cfg.AllowWrite {
			return nil, errors.New("allow_write is required")
		}
		document := bson.D{}
		if tool != "mongo_delete" && bson.UnmarshalExtJSON([]byte(in.Document), false, &document) != nil {
			return nil, errors.New("invalid Extended JSON document")
		}
		switch tool {
		case "mongo_insert":
			_, err = collection.InsertOne(ctx, document)
		case "mongo_update":
			_, err = collection.UpdateOne(ctx, filter, document)
		case "mongo_delete":
			_, err = collection.DeleteOne(ctx, filter)
		}
		if err != nil {
			return nil, errors.New("MongoDB write failed; outcome may be unknown, do not automatically retry")
		}
		return map[string]any{"completed": true}, nil
	default:
		return nil, errors.New("unsupported MongoDB operation")
	}
	if err != nil {
		return nil, errors.New("MongoDB query failed")
	}
	defer cursor.Close(ctx)
	docs := []string{}
	size := 0
	truncated := false
	for cursor.Next(ctx) {
		raw, err := bson.MarshalExtJSON(cursor.Current, true, false)
		if err != nil {
			return nil, errors.New("MongoDB result encoding failed")
		}
		if len(docs) >= in.Limit || size+len(raw) > MaxBytes/2 {
			truncated = true
			break
		}
		docs = append(docs, string(raw))
		size += len(raw)
	}
	if cursor.Err() != nil {
		return nil, errors.New("MongoDB result interrupted")
	}
	return map[string]any{"documents": docs, "format": "canonical_extended_json", "truncated": truncated}, nil
}
func writesPipeline(value any) bool {
	switch v := value.(type) {
	case mongo.Pipeline:
		for _, x := range v {
			if writesPipeline(x) {
				return true
			}
		}
	case bson.D:
		for _, e := range v {
			if e.Key == "$out" || e.Key == "$merge" || writesPipeline(e.Value) {
				return true
			}
		}
	case bson.A:
		for _, x := range v {
			if writesPipeline(x) {
				return true
			}
		}
	}
	return false
}
