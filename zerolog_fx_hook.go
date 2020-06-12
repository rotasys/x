package x

import (
	"github.com/rs/zerolog"
)

type ZerologFXHook struct {
	zerolog *zerolog.Logger
}

func (z *ZerologFXHook) HandleError(err error) {
	z.zerolog.Error().Err(err).Msg("FX failed to initalize")
}
