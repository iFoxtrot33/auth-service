package kafka

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

type Producer interface {
	SendUserAuthenticated(ctx context.Context, userID, provider, sessionID string, tokens *ProviderTokens) error
	SendUserLogout(ctx context.Context, sessionID string) error
	Close() error
}

type KafkaProducer struct {
	writer *kafka.Writer
	logger zerolog.Logger
}

type ProducerConfig struct {
	Brokers      []string
	Topic        string
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	Logger       zerolog.Logger
}

func NewProducer(config ProducerConfig) Producer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(config.Brokers...),
		Topic:        config.Topic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireOne,
		Async:        false,
		BatchTimeout: 10 * time.Millisecond,
		WriteTimeout: config.WriteTimeout,
		ReadTimeout:  config.ReadTimeout,
	}

	return &KafkaProducer{
		writer: writer,
		logger: config.Logger,
	}
}

func (p *KafkaProducer) SendUserAuthenticated(ctx context.Context, userID, provider, sessionID string, tokens *ProviderTokens) error {
	message := UserAuthenticatedMessage{
		Type:           MessageTypeUserAuthenticated,
		UserID:         userID,
		Provider:       provider,
		SessionID:      sessionID,
		ProviderTokens: tokens,
		Timestamp:      time.Now(),
	}

	return p.sendMessage(ctx, message)
}

func (p *KafkaProducer) SendUserLogout(ctx context.Context, sessionID string) error {
	message := UserLogoutMessage{
		Type:      MessageTypeUserLogout,
		SessionID: sessionID,
		Timestamp: time.Now(),
	}

	return p.sendMessage(ctx, message)
}

func (p *KafkaProducer) sendMessage(ctx context.Context, message interface{}) error {
	messageBytes, err := json.Marshal(message)
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to marshal message")
		return err
	}

	kafkaMessage := kafka.Message{
		Key:   []byte(generateMessageKey(message)),
		Value: messageBytes,
		Time:  time.Now(),
	}

	err = p.writer.WriteMessages(ctx, kafkaMessage)
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to write message to Kafka")
		return err
	}

	p.logger.Info().
		Str("message_type", getMessageType(message)).
		Str("message_key", string(kafkaMessage.Key)).
		Msg("Successfully sent message to Kafka")

	return nil
}

func generateMessageKey(message interface{}) string {
	switch msg := message.(type) {
	case UserAuthenticatedMessage:
		return msg.UserID
	case UserLogoutMessage:
		return msg.SessionID
	default:
		return "unknown"
	}
}

func getMessageType(message interface{}) string {
	switch msg := message.(type) {
	case UserAuthenticatedMessage:
		return msg.Type
	case UserLogoutMessage:
		return msg.Type
	default:
		return "unknown"
	}
}

func (p *KafkaProducer) Close() error {
	return p.writer.Close()
}
