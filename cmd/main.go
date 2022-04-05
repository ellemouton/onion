package main

import (
	"encoding/hex"
	"fmt"
	"github.com/urfave/cli"
	"log"
	"onion"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "onion"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "user",
			Usage: "The user the command is for. Options " +
				"include: alice, bob, charlie, dave",
			Required: true,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "info",
			Action: nodeInfo,
		},
		{
			Name:   "build",
			Action: buildOnion,
		},
		{
			Name:   "parse",
			Action: parseOnion,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "payload",
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func nodeInfo(ctx *cli.Context) error {
	// Get user.
	user, err := onion.GetUser(ctx.GlobalString("user"))
	if err != nil {
		return err
	}

	fmt.Printf("%s's public key is: %s\n", user.Name,
		hex.EncodeToString(user.PubKey.SerializeCompressed()))

	return nil
}

func buildOnion(ctx *cli.Context) error {
	fmt.Println("Provide the hops and the messages you want to deliver to each")

	return nil
}

func parseOnion(ctx *cli.Context) error {
	fmt.Println("parsing onion!")

	return nil
}
