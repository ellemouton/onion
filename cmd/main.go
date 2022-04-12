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
						cli.StringFlag{
							Name:  "blindedRoute",
							Usage: "encoded blinded route",
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
				cli.StringFlag{
					Name: "ephemeral",
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
			PubKey:    user.PubKey,
			ClearData: []byte(payload),
		}
	}

	return hopsData, nil
}

func buildOnion(ctx *cli.Context) error {
	blindedRoute := ctx.String("blindedRoute")
	if blindedRoute != "" {
		return buildOnionWithBlindedPath(ctx)
	}

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

	fmt.Printf("Onion: %s\n", hex.EncodeToString(leOnion.Serialize()))
	fmt.Printf("Give this onion to: %s\n",
		onion.UserIndex[string(hopsData[0].PubKey.SerializeCompressed())])

	return nil
}

func buildOnionWithBlindedPath(ctx *cli.Context) error {
	blindedRouteB, err := hex.DecodeString(ctx.String("blindedRoute"))
	if err != nil {
		return err
	}

	blindedPath, err := onion.DecodeBlindedPath(blindedRouteB)
	if err != nil {
		return err
	}

	// Get clear-text hops.
	hopsStr := ctx.String("hops")
	hops := strings.Split(hopsStr, ",")

	// Get the payloads for each hop (the payload from the sender hop).
	// Ensure that the number of payloads == number of blinded hops + num
	// clear text hops.
	pl := ctx.String("payloads")
	var payloads []string
	payloads = strings.Split(pl, ",")
	if len(payloads) != len(hops)+len(blindedPath.BlindedNodeIDs) {
		return errors.New(fmt.Sprintf("num payloads (%d) does not "+
			"match num hops (%d)", len(payloads),
			len(hops)+len(blindedPath.BlindedNodeIDs)))
	}

	// Before we continue, ensure that the last clear-text hop is the same
	// as the entry point hop in the blinded path.
	user, err := onion.GetUser(hops[len(hops)-1])
	if err != nil {
		return err
	}

	if !user.PubKey.IsEqual(blindedPath.EntryNodeID) {
		return fmt.Errorf("last clear text hop is not equal to the " +
			"blinded path entry point hop")
	}

	// Gather all the info for each hop along the full path.
	hopsData := make(
		[]*onion.HopData,
		len(hops)+len(blindedPath.BlindedNodeIDs),
	)

	hopIndex := 0
	// First, add all the clear text hops (all the ones before the entry
	// point hop).
	for _, hop := range hops[:len(hops)-1] {
		user, err := onion.GetUser(hop)
		if err != nil {
			return err
		}

		payload := payloads[hopIndex]

		hopsData[hopIndex] = &onion.HopData{
			PubKey:    user.PubKey,
			ClearData: []byte(payload),
		}

		hopIndex++
	}

	// Now we add the entry node hop. This is the only hop to which we
	// also need to add the ephemeral point.
	hopsData[hopIndex] = &onion.HopData{
		PubKey:        blindedPath.EntryNodeID,
		ClearData:     []byte(payloads[hopIndex]),
		EncryptedData: blindedPath.EncryptedData[0],
		EphemeralKey:  blindedPath.FirstBlindingEphemeralKey,
	}

	hopIndex++

	// Now we can add the blinded hops. For these, we need to include the
	// encrypted data from the recipient.
	for i, id := range blindedPath.BlindedNodeIDs {
		hopsData[hopIndex] = &onion.HopData{
			PubKey:        id,
			ClearData:     []byte(payloads[hopIndex]),
			EncryptedData: blindedPath.EncryptedData[i+1],
		}

		hopIndex++
	}

	sessionKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	leOnion, err := onion.BuildOnion(sessionKey, hopsData)
	if err != nil {
		return err
	}

	fmt.Println("-------------------------------------------------------")
	fmt.Println("Onion: ", hex.EncodeToString(leOnion.Serialize()))
	fmt.Printf("Give this onion to: %s\n",
		onion.UserIndex[string(hopsData[0].PubKey.SerializeCompressed())])
	fmt.Println("-------------------------------------------------------")

	return nil
}

func parseOnion(ctx *cli.Context) error {
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

	ep := ctx.String("ephemeral")
	if ep != "" {
		epb, err := hex.DecodeString(ep)
		if err != nil {
			return err
		}

		nextEphemeral, err := btcec.ParsePubKey(epb)
		if err != nil {
			return err
		}

		onionPacket.EphemeralKey = nextEphemeral
	}

	myPayload, nextOnion, err := onion.Peel(user, onionPacket)
	if err != nil {
		return err
	}

	hopData, err := onion.DecodeHopDataPayload(myPayload.Payload)
	if err != nil {
		return err
	}

	fmt.Println("-------------------------------------------------------")
	fmt.Println("Payload from Sender: \"", string(hopData.ClearData), "\"")
	fmt.Println("Payload from Recipient: \"",
		string(myPayload.DecryptedDataFromRecipient), "\"")

	if myPayload.FwdTo == nil {
		fmt.Println("Final hop! Can chill now")
		return nil
	}

	fmt.Println("Onion: ", hex.EncodeToString(nextOnion.Serialize()))
	fmt.Println("Should forward onion onto: ",
		onion.UserIndex[string(myPayload.FwdTo.SerializeCompressed())])

	if nextOnion.EphemeralKey != nil {
		fmt.Printf("Next Ephemeral: %x\n",
			nextOnion.EphemeralKey.SerializeCompressed())
	}
	fmt.Println("-------------------------------------------------------")

	return nil
}
