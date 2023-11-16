package server

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/authgear/authgear-server/pkg/util/log"
)

type Spec struct {
	Name          string
	ListenAddress string
	HTTPS         bool
	CertFilePath  string
	KeyFilePath   string
	Handler       http.Handler
}

func Start(ctx context.Context, logger *log.Logger, specs []Spec) {
	ctx, stopReceivingSignal := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopReceivingSignal()

	type shutdownStruct struct {
		Name     string
		Shutdown func(context.Context) error
	}

	var shutdowns []shutdownStruct
	for _, spec := range specs {
		// Capture spec
		spec := spec

		shutdown := StartOne(ctx, logger, spec)
		shutdowns = append(shutdowns, shutdownStruct{
			Name:     spec.Name,
			Shutdown: shutdown,
		})
	}

	<-ctx.Done()
	logger.Infof("received signal, shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, shutdownStruct := range shutdowns {
		shutdownStruct := shutdownStruct
		go func() {
			logger.Infof("stopping %v...", shutdownStruct.Name)
			err := shutdownStruct.Shutdown(shutdownCtx)
			if err != nil {
				logger.WithError(err).Errorf("failed to stop gracefully %v", shutdownStruct.Name)
			}
		}()
	}
}

func StartOne(ctx context.Context, logger *log.Logger, spec Spec) (shutdown func(ctx context.Context) error) {
	httpServer := &http.Server{
		Addr:              spec.ListenAddress,
		Handler:           spec.Handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	shutdown = func(ctx context.Context) error {
		return httpServer.Shutdown(ctx)
	}

	listenErr := make(chan error, 1)
	go func() {
		if spec.HTTPS {
			logger.Infof("starting %v on https://%v", spec.Name, spec.ListenAddress)
			listenErr <- httpServer.ListenAndServeTLS(spec.CertFilePath, spec.KeyFilePath)
		} else {
			logger.Infof("starting %v on http://%v", spec.Name, spec.ListenAddress)
			listenErr <- httpServer.ListenAndServe()
		}
	}()

	go func() {
		select {
		case err := <-listenErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Fatalf("failed to start %v", spec.Name)
			}
			return
		case <-ctx.Done():
			return
		}
	}()

	return
}
