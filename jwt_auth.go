package x

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/square/go-jose/jwt"
)

type JWTConfig struct {
	FailedAuthHandler AuthenticationFailedHandler
	Header            string
	Key               interface{}
}

type AuthenticationFailedHandler func(c *gin.Context, err error)

func NewJWTConfig() JWTConfig {
	return JWTConfig{
		Header: "Authorization",
	}
}

func loadPublicKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err0 := x509.ParsePKIXPublicKey(input)
	if err0 == nil {
		return pub, nil
	}

	cert, err1 := x509.ParseCertificate(input)
	if err1 == nil {
		return cert.PublicKey, nil
	}

	jwk, err2 := LoadJSONWebKey(data, true)
	if err2 == nil {
		return jwk, nil
	}

	return nil, errors.New("parse error, invalid public key")
}

func loadPrivateKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	jwk, err3 := LoadJSONWebKey(input, false)
	if err3 == nil {
		return jwk, nil
	}

	return nil, errors.New("parse error, invalid private key")
}

func (j *JWTConfig) AddPublicKey(data []byte) error {
	key, err := loadPublicKey(data)
	if err == nil {
		j.Key = key
		return nil
	}
	key, err = loadPrivateKey(data)
	if err == nil {
		j.Key = key
		return nil
	}
	return err
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
