package gapi

import (
	"fmt"
	db "github.com/Dejan91/simple_bank/db/sqlc"
	"github.com/Dejan91/simple_bank/pb"
	"github.com/Dejan91/simple_bank/token"
	"github.com/Dejan91/simple_bank/util"
	"github.com/Dejan91/simple_bank/worker"
)

// Server serves gRPS requests for our banking service
type Server struct {
	pb.UnimplementedSimpleBankServer
	config          util.Config
	store           db.Store
	tokenMaker      token.Maker
	taskDistributor worker.TaskDistributor
}

// NewServer creates a new gRPC server
func NewServer(config util.Config, store db.Store, taskDistributor worker.TaskDistributor) (*Server, error) {
	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}

	server := &Server{
		config:          config,
		store:           store,
		tokenMaker:      tokenMaker,
		taskDistributor: taskDistributor,
	}

	return server, nil
}
