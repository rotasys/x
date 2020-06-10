package x

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/square/go-jose/jwt"
)

type JWTConfig struct {
	Claims            jwt.Claims
	FailedAuthHandler AuthenticationFailedHandler
	Header            string
	Key               interface{}
}

type AuthenticationFailedHandler func(c *gin.Context, err error)

func NewJWTConfig(sub string, iss string, aud jwt.Audience) JWTConfig {
	return JWTConfig{
		Claims: jwt.Claims{
			Subject:   sub,
			Issuer:    iss,
			NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
			Expiry:    jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 15, 0, 0, time.UTC)),
			Audience:  aud,
		},
		Header: "Authorization",
	}
}

func (j *JWTConfig) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtHeader := c.GetHeader(j.Header)
		tok, err := jwt.ParseSigned(jwtHeader)
		if err != nil {
			if j.FailedAuthHandler != nil {
				j.FailedAuthHandler(c, err)
				return
			}
			c.AbortWithError(401, err)
			return
		}

		out := make(map[string]interface{})
		if err := tok.Claims(nil, &out); err != nil {
			if j.FailedAuthHandler != nil {
				j.FailedAuthHandler(c, err)
				return
			}
			c.AbortWithError(401, err)
			return
		}

		c.Set("jwt", out)
		c.Next()
	}
}
