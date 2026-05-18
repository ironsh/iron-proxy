package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3SinkConfig struct {
	Bucket        string
	Prefix        string
	Region        string
	QueueSize     int
	MaxBatch      int
	FlushInterval time.Duration
}

type S3Sink struct {
	client        s3PutObjectAPI
	bucket        string
	prefix        string
	events        chan Event
	done          chan struct{}
	closeOnce     sync.Once
	maxBatch      int
	flushInterval time.Duration
	logger        *slog.Logger
}

type s3PutObjectAPI interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func NewS3Sink(ctx context.Context, cfg S3SinkConfig, logger *slog.Logger) (*S3Sink, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("usage_events.s3.bucket is required")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}

	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	s := &S3Sink{
		client:        s3.NewFromConfig(awsCfg),
		bucket:        cfg.Bucket,
		prefix:        strings.Trim(cfg.Prefix, "/"),
		events:        make(chan Event, cfg.QueueSize),
		done:          make(chan struct{}),
		maxBatch:      cfg.MaxBatch,
		flushInterval: cfg.FlushInterval,
		logger:        logger,
	}
	go s.run()
	return s, nil
}

func (s *S3Sink) TryEnqueue(event Event) bool {
	select {
	case s.events <- event:
		return true
	default:
		return false
	}
}

func (s *S3Sink) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		close(s.events)
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *S3Sink) run() {
	defer close(s.done)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, s.maxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.putBatch(context.Background(), batch); err != nil && s.logger != nil {
			s.logger.Error("writing usage event batch to S3",
				slog.String("bucket", s.bucket),
				slog.String("prefix", s.prefix),
				slog.Int("events", len(batch)),
				slog.String("error", err.Error()),
			)
		}
		batch = batch[:0]
	}

	for {
		select {
		case event, ok := <-s.events:
			if !ok {
				flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= s.maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *S3Sink) putBatch(ctx context.Context, batch []Event) error {
	var body bytes.Buffer
	for _, event := range batch {
		line, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshaling event: %w", err)
		}
		body.Write(line)
		body.WriteByte('\n')
	}

	key := s.key(batch[0].TS)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body.Bytes()),
		ContentType: aws.String("application/x-ndjson"),
	})
	if err != nil {
		return fmt.Errorf("put object %s: %w", key, err)
	}
	return nil
}

func (s *S3Sink) key(ts time.Time) string {
	ts = ts.UTC()
	parts := []string{
		s.prefix,
		"schema_version=1",
		fmt.Sprintf("date=%04d-%02d-%02d", ts.Year(), ts.Month(), ts.Day()),
		fmt.Sprintf("hour=%02d", ts.Hour()),
		fmt.Sprintf("%d.ndjson", ts.UnixNano()),
	}
	return path.Join(parts...)
}
