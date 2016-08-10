// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package client

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/keybase/cli"
	"github.com/keybase/client/go/libcmdline"
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
	rpc "github.com/keybase/go-framed-msgpack-rpc"
)

type CmdSigsRevoke struct {
	libkb.Contextified
	queries []string
}

func (c *CmdSigsRevoke) ParseArgv(ctx *cli.Context) error {
	if len(ctx.Args()) == 0 {
		return fmt.Errorf("No arguments given to sigs revoke.")
	}

	for _, arg := range ctx.Args() {
		if len(arg) < keybase1.SigIDQueryMin {
			return fmt.Errorf("sig id %q is too short; must be at least 16 characters long", arg)
		}
		c.queries = append(c.queries, arg)
	}

	return nil
}

func (c *CmdSigsRevoke) Run() error {
	cli, err := GetRevokeClient(c.G())
	if err != nil {
		return err
	}

	protocols := []rpc.Protocol{
		NewSecretUIProtocol(c.G()),
	}
	if err = RegisterProtocolsWithContext(protocols, c.G()); err != nil {
		return err
	}

	return cli.RevokeSigs(context.TODO(), keybase1.RevokeSigsArg{
		SigIDQueries: c.queries,
	})
}

func NewCmdSigsRevoke(cl *libcmdline.CommandLine, g *libkb.GlobalContext) cli.Command {
	return cli.Command{
		Name:         "revoke",
		ArgumentHelp: "<sig-id>",
		Usage:        "revoke a signature by sig ID",
		Action: func(c *cli.Context) {
			cl.ChooseCommand(&CmdSigsRevoke{Contextified: libkb.NewContextified(g)}, "revoke", c)
		},
		Flags: nil,
	}
}

func (c *CmdSigsRevoke) GetUsage() libkb.Usage {
	return libkb.Usage{
		Config:     true,
		GpgKeyring: true,
		KbKeyring:  true,
		API:        true,
	}
}
