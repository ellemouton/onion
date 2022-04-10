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
			Name: "build",
			Subcommands: cli.Commands{
				{
					Name:   "onion",
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
					Name: "blindedRoute",
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
					}, Action: buildBlindedRoute,
				},
			},
		},
		{
			Name:   "parse",
			Action: parseOnion,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "payload",
					Required: true,
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

func buildBlindedRoute(ctx *cli.Context) error {
	hopsData, err := parseHopData(ctx)
	if err != nil {
		return err
	}

	user, err := onion.GetUser(ctx.GlobalString("user"))
	if err != nil {
		return err
	}

	if !hopsData[len(hopsData)-1].PubKey.IsEqual(user.PubKey) {
		return fmt.Errorf("last hop must be same as user")
	}

	ephemeralKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	blindedPath, err := onion.BuildBlindedPath(ephemeralKey, hopsData)
	if err != nil {
		return err
	}

	fmt.Println(blindedPath)
	return nil
}

func parseHopData(ctx *cli.Context) ([]*onion.HopData, error) {
	hopsStr := ctx.String("hops")
	hops := strings.Split(hopsStr, ",")

	pl := ctx.String("payloads")
	var payloads []string
	if pl != "" {
		payloads = strings.Split(pl, ",")
		if len(payloads) != len(hops) {
			return nil, errors.New(fmt.Sprintf("num payloads (%d) "+
				"does not match num hops (%d)", len(payloads),
				len(hops)))
		}
	}

	reader := bufio.NewReader(os.Stdin)
	hopsData := make([]*onion.HopData, len(hops))
	for i, hop := range hops {
		user, err := onion.GetUser(hop)
		if err != nil {
			return nil, err
		}

		payload := ""
		if len(payloads) == 0 {
			fmt.Printf("Enter message for %s: ", user.Name)
			payload, err = reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
		} else {
			payload = payloads[i]
		}

		hopsData[i] = &onion.HopData{
			PubKey:  user.PubKey,
			Payload: []byte(payload),
		}
	}

	return hopsData, nil
}

func buildOnion(ctx *cli.Context) error {
	hopsData, err := parseHopData(ctx)
	if err != nil {
		return err
	}

	sessionKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	leOnion, err := onion.BuildOnion(sessionKey, hopsData)
	if err != nil {
		return err
	}

	fmt.Println("Onion: ", hex.EncodeToString(leOnion.Serialize()))

	return nil
}

func parseOnion(ctx *cli.Context) error {
	fmt.Println("parsing onion!")

	payload, err := hex.DecodeString(ctx.String("payload"))
	if err != nil {
		return err
	}

	onionPacket, err := onion.DeserializeOnion(payload)
	if err != nil {
		return err
	}

	// Get user.
	user, err := onion.GetUser(ctx.GlobalString("user"))
	if err != nil {
		return err
	}

	myPayload, nextOnion, err := onion.Peel(user, onionPacket)
	if err != nil {
		return err
	}

	fmt.Println("My payload: \"", string(myPayload.Payload), "\"")

	if myPayload.FwdTo == nil {
		fmt.Println("Final hop! Can chill now")
		return nil
	}

	fmt.Println("Should forward onion onto: ",
		onion.UserIndex[string(myPayload.FwdTo.SerializeCompressed())])
	fmt.Println("Onion: ", hex.EncodeToString(nextOnion.Serialize()))

	return nil
}
