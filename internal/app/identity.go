package app

import (
	"context"
	"errors"

	"github.com/raydalsayf/gitseal/internal/identity"
	"github.com/raydalsayf/gitseal/internal/localstate"
)

func IdentityCreate(ctx context.Context, name string) (identity.Record, error) {
	return identity.Create(ctx, name)
}

func IdentityUse(ctx context.Context, cwd, name string) (record identity.Record, resultErr error) {
	record, err := identity.Load(name)
	if err != nil {
		return identity.Record{}, err
	}
	w, err := Open(ctx, cwd)
	if err != nil {
		return identity.Record{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	if err := localstate.SaveSelection(ctx, w.Repo.GitSealDir(), name); err != nil {
		return identity.Record{}, err
	}
	return record, nil
}

func IdentityShow(ctx context.Context, cwd, override string) (identity.Record, error) {
	name := override
	if name == "" {
		w, err := Open(ctx, cwd)
		if err != nil {
			return identity.Record{}, err
		}
		name, err = localstate.LoadSelection(w.Repo.GitSealDir())
		closeErr := w.Close()
		if err != nil || closeErr != nil {
			return identity.Record{}, errors.Join(err, closeErr)
		}
	}
	if name == "" {
		return identity.Record{}, errors.New("no local identity selected; use gitseal identity use NAME or --identity NAME")
	}
	return identity.Load(name)
}

func (w *Workspace) SelectedIdentity(override string) (identity.Record, error) {
	name := override
	var err error
	if name == "" {
		name, err = localstate.LoadSelection(w.Repo.GitSealDir())
		if err != nil {
			return identity.Record{}, err
		}
	}
	if name == "" {
		return identity.Record{}, errors.New("no local identity selected; use gitseal identity use NAME or --identity NAME")
	}
	return identity.Load(name)
}
