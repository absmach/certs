package service

import "github.com/absmach/certs/pkg/errors"


var (
	// ErrNotFound indicates a non-existent entity request.
	ErrNotFound = errors.New("entity not found")

	// ErrAuthentication indicates failure occurred while authenticating the entity.
	ErrAuthentication = errors.New("failed to perform authentication over the entity")

	// ErrAuthorization indicates failure occurred while authorizing the entity.
	ErrAuthorization = errors.New("failed to perform authorization over the entity")

	// ErrConflict indicates that entity already exists.
	ErrConflict = errors.New("entity already exists")

	// ErrCreateEntity indicates error in creating entity or entities.
	ErrCreateEntity = errors.New("failed to create entity")

	// ErrRemoveEntity indicates error in removing entity.
	ErrRemoveEntity = errors.New("failed to remove entity")

	// ErrViewEntity indicates error in viewing entity or entities.
	ErrViewEntity = errors.New("view entity failed")

	// ErrUpdateEntity indicates error in updating entity or entities.
	ErrUpdateEntity = errors.New("update entity failed")

	// ErrMalformedEntity indicates a malformed entity specification.
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrNoCaCertKey indicates that the CA certificate or key is missing.
	ErrNoCaCertKey = errors.New("CA certificate or key is missing")
)