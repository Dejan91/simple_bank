package gapi

import (
	"context"
	"database/sql"
	db "github.com/Dejan91/simple_bank/db/sqlc"
	"github.com/Dejan91/simple_bank/pb"
	"github.com/Dejan91/simple_bank/util"
	"github.com/Dejan91/simple_bank/val"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

func (s *Server) UpdateUser(ctx context.Context, r *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	authPayload, err := s.authorizeUser(ctx)
	if err != nil {
		return nil, unauthenticatedError(err)
	}

	violations := validateUpdateUserRequest(r)
	if violations != nil {
		return nil, invalidArgumentError(violations)
	}

	if authPayload.Username != r.GetUsername() {
		return nil, status.Errorf(codes.PermissionDenied, "cannot update other user's info")
	}

	arg := db.UpdateUserParams{
		Username: r.GetUsername(),
		FullName: sql.NullString{
			String: r.GetFullName(),
			Valid:  r.FullName != nil,
		},
		Email: sql.NullString{
			String: r.GetEmail(),
			Valid:  r.Email != nil,
		},
	}

	if r.Password != nil {
		hashedPassword, err := util.HashPassword(r.GetPassword())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to hash password: %s", err)
		}

		arg.HashedPassword = sql.NullString{
			String: hashedPassword,
			Valid:  true,
		}

		arg.PasswordChangedAt = sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		}
	} else {
		arg.PasswordChangedAt = sql.NullTime{
			Valid: false,
		}
	}

	user, err := s.store.UpdateUser(ctx, arg)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to update user: %s", err)
	}

	rsp := &pb.UpdateUserResponse{
		User: convertUser(user),
	}

	return rsp, nil
}

func validateUpdateUserRequest(r *pb.UpdateUserRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := val.ValidateUsername(r.GetUsername()); err != nil {
		violations = append(violations, fieldViolation("username", err))
	}

	if r.Password != nil {
		if err := val.ValidatePassword(r.GetPassword()); err != nil {
			violations = append(violations, fieldViolation("password", err))
		}
	}

	if r.FullName != nil {
		if err := val.ValidateFullName(r.GetFullName()); err != nil {
			violations = append(violations, fieldViolation("full_name", err))
		}
	}

	if r.Username != "" {
		if err := val.ValidateEmail(r.GetUsername()); err != nil {
			violations = append(violations, fieldViolation("email", err))
		}
	}

	return violations
}
