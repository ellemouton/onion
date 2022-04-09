package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/urfave/cli"
	"log"
	"onion"
	"os"
	"strings"
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
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "hops",
					Usage:    "structure: hop1_alias,hop2_alias,...",
					Required: true,
				},
				cli.StringFlag{
					Name:  "payloads",
					Usage: "structure: payload 1,payload 2,...",
				},
			},
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
	hopsStr := ctx.String("hops")
	hops := strings.Split(hopsStr, ",")

	pl := ctx.String("payloads")

	var payloads []string
	if pl != "" {
		payloads = strings.Split(pl, ",")
		if len(payloads) != len(hops) {
			return errors.New(fmt.Sprintf("num payloads (%d) "+
				"does not match num hops (%d)", len(payloads),
				len(hops)))
		}
	}

	reader := bufio.NewReader(os.Stdin)
	hopsData := make([]*onion.HopData, len(hops))
	for i, hop := range hops {
		user, err := onion.GetUser(hop)
		if err != nil {
			return err
		}

		payload := ""
		if len(payloads) == 0 {
			fmt.Printf("Enter message for %s: ", user.Name)
			payload, err = reader.ReadString('\n')
			if err != nil {
				return err
			}
		} else {
			payload = payloads[i]
		}

		hopsData[i] = &onion.HopData{
			PubKey:  user.PubKey,
			Payload: []byte(payload),
		}
	}

	//sessionKey, err := btcec.NewPrivateKey()
	//if err != nil {
	//	return err
	//}

	b, _ := hex.DecodeString("6088af09c88b007b953cc12e28e88f119465eb6b4279a3f1cfc613f1df3ec848")
	priv, _ := btcec.PrivKeyFromBytes(b)

	leOnion, err := onion.BuildOnion(priv, hopsData)
	if err != nil {
		return err
	}

	fmt.Println("Onion: ", hex.EncodeToString(leOnion.Serialize()))

	return nil
}

func parseOnion(ctx *cli.Context) error {
	fmt.Println("parsing onion!")

	return nil
}
