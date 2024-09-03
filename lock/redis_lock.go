package lock

import (
	"context"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"time"
)

func Lock(ctx context.Context, logger *zap.Logger, redisClient redis.UniversalClient, key string, ttl time.Duration) (bool, error) {
	return redisClient.SetNX(ctx, key, "1", ttl).Result()
}
