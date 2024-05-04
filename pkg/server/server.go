package server

import (
	"context"
	"encoding/base64"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"strings"
)

type Server struct {
	kms.UnimplementedKMSServiceServer

	logger *slog.Logger
	client *vault.Client

	vaultRequestOption vault.RequestOption
}

func wrapError(err error) error {
	if strings.Contains(err.Error(), "403 Forbidden") {
		return status.Error(codes.PermissionDenied, "Forbidden")
	}

	return status.Error(codes.Internal, "Internal Error")
}

func (s Server) Seal(ctx context.Context, request *kms.Request) (*kms.Response, error) {
	s.logger.InfoContext(ctx, "Sealing data", "node", request.NodeUuid)

	req := schema.TransitEncryptRequest{Plaintext: base64.StdEncoding.EncodeToString(request.Data)}
	res, err := s.client.Secrets.TransitEncrypt(ctx, request.NodeUuid, req, s.vaultRequestOption)

	if err != nil {
		s.logger.ErrorContext(ctx, "Error while sealing data", "node", request.NodeUuid, "error", err)
		return nil, wrapError(err)
	}

	data := []byte(res.Data["ciphertext"].(string))

	return &kms.Response{Data: data}, nil
}

func (s Server) Unseal(ctx context.Context, request *kms.Request) (*kms.Response, error) {
	s.logger.Info("Unsealing data", "node", request.NodeUuid)

	req := schema.TransitDecryptRequest{Ciphertext: string(request.Data)}
	res, err := s.client.Secrets.TransitDecrypt(ctx, request.NodeUuid, req, s.vaultRequestOption)

	if err != nil {
		s.logger.ErrorContext(ctx, "Error while unsealing data", "node", request.NodeUuid, "error", err)
		return nil, wrapError(err)
	}

	data, err := base64.StdEncoding.DecodeString(res.Data["plaintext"].(string))
	if err != nil {
		return nil, wrapError(err)
	}

	return &kms.Response{Data: data}, nil
}

func NewServer(client *vault.Client, logger *slog.Logger, mountPath string) *Server {
	return &Server{client: client, logger: logger, vaultRequestOption: vault.WithMountPath(mountPath)}
}
