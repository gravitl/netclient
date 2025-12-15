package exporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"

	pbflow "github.com/gravitl/netmaker/grpc/flow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	DefaultBatchSize    = 200
	DefaultBatchTime    = 30 * time.Second
	DefaultRetryCount   = 3
	DefaultRetryBackoff = 300 * time.Millisecond
)

type Options struct {
	tlsCreds     credentials.TransportCredentials
	batchSize    int
	batchTime    time.Duration
	retryCount   int
	retryBackoff time.Duration
}

func WithTLS(cfg *tls.Config) func(*Options) {
	return func(o *Options) { o.tlsCreds = credentials.NewTLS(cfg) }
}
func WithBatchSize(n int) func(*Options) {
	return func(o *Options) { o.batchSize = n }
}
func WithBatchTime(t time.Duration) func(*Options) {
	return func(o *Options) { o.batchTime = t }
}
func WithRetryPolicy(count int, backoff time.Duration) func(*Options) {
	return func(o *Options) {
		o.retryCount = count
		o.retryBackoff = backoff
	}
}

type FlowGrpcClient struct {
	serverAddr string
	opts       Options

	conn   *grpc.ClientConn
	stream pbflow.FlowService_StreamFlowsClient

	mu     sync.Mutex
	events []*pbflow.FlowEvent

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewFlowGrpcClient(serverURL string, optFns ...func(*Options)) *FlowGrpcClient {
	opts := Options{
		tlsCreds:     nil,
		batchSize:    DefaultBatchSize,
		batchTime:    DefaultBatchTime,
		retryCount:   DefaultRetryCount,
		retryBackoff: DefaultRetryBackoff,
	}
	for _, fn := range optFns {
		fn(&opts)
	}

	return &FlowGrpcClient{
		serverAddr: serverURL,
		opts:       opts,
		stopCh:     make(chan struct{}),
	}
}

func (c *FlowGrpcClient) Start() error {
	if err := c.connect(); err != nil {
		return err
	}

	c.wg.Add(1)
	go c.batchLoop()

	return nil
}

func (c *FlowGrpcClient) Stop() error {
	close(c.stopCh)
	c.wg.Wait()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *FlowGrpcClient) Export(event *pbflow.FlowEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.events = append(c.events, event)
	if len(c.events) >= c.opts.batchSize {
		go c.flush()
	}
	return nil
}

func (c *FlowGrpcClient) batchLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.opts.batchTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.flush()
		case <-c.stopCh:
			c.flush()
			return
		}
	}
}

func (c *FlowGrpcClient) flush() {
	c.mu.Lock()
	if len(c.events) == 0 {
		c.mu.Unlock()
		return
	}
	evs := c.events
	c.events = nil
	c.mu.Unlock()

	env := &pbflow.FlowEnvelope{
		Events: evs,
	}

	err := c.sendWithRetries(env)
	if err != nil {
		fmt.Println("[flow] permanently dropped batch:", err)
	}
}

func (c *FlowGrpcClient) sendWithRetries(env *pbflow.FlowEnvelope) error {
	var err error

	for attempt := 1; attempt <= c.opts.retryCount; attempt++ {
		err = c.sendOnce(env)
		if err == nil {
			return nil
		}

		fmt.Printf("[flow] send attempt %d failed: %v\n", attempt, err)
		time.Sleep(c.opts.retryBackoff)
	}

	return fmt.Errorf("retry limit exceeded: %w", err)
}

func (c *FlowGrpcClient) sendOnce(env *pbflow.FlowEnvelope) error {
	if c.stream == nil {
		err := c.reconnect()
		if err != nil {
			return err
		}
	}

	err := c.stream.Send(env)
	if err != nil {
		return c.handleStreamError(err)
	}

	resp, err := c.stream.Recv()
	if err != nil {
		return c.handleStreamError(err)
	}

	if !resp.Success {
		return fmt.Errorf("server rejected: %s", resp.Error)
	}

	return nil
}

func (c *FlowGrpcClient) connect() error {
	var dialOpts []grpc.DialOption

	if c.opts.tlsCreds != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(c.opts.tlsCreds))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(c.serverAddr, dialOpts...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	c.conn = conn

	client := pbflow.NewFlowServiceClient(conn)

	// The stream should live beyond dial timeout → use background context
	stream, err := client.StreamFlows(context.Background())
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	c.stream = stream
	return nil
}

func (c *FlowGrpcClient) reconnect() error {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.stream = nil
	time.Sleep(300 * time.Millisecond)
	return c.connect()
}

func (c *FlowGrpcClient) handleStreamError(err error) error {
	if err == io.EOF {
		recErr := c.reconnect()
		if recErr != nil {
			return recErr
		}

		return fmt.Errorf("stream closed: %w", err)
	}
	st, ok := status.FromError(err)
	if ok {
		return fmt.Errorf("grpc status: %s", st.Message())
	}
	return err
}
