package x

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/uniplaces/carbon"
)

type GinZerolog struct {
}

func (g *GinZerolog) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		preTime := carbon.Now()

		c.Next()

		log.Debug().Time("request-time", preTime.Time).TimeDiff("latency", carbon.Now().Time, preTime.Time).Str("content-type", c.ContentType()).Str("path", c.Request.URL.EscapedPath()).Send()
	}
}
