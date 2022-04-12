# Onion + Route Blinding

CLI tool for constructing & peeling onions both with and without route blinding.

- Repo for playing around with onion wrapping and peeling both 
with and without route blinding.
- Onion works as is stated in [Bolt 4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md): 
- Route Blinding proposal can be found [here](https://github.com/lightning/bolts/blob/route-blinding/proposals/route-blinding.md)
- Tis very rough and not at all pretty.

## Example 1: Normal Onion (no blinded hops) 

We assume the following node setup:

```
Alice <-> Bob <-> Charlie <-> Dave
```
### Building the onion:

You can instruct Alice to build an onion packet as follows. 
Use the `--hops` arg to specify the order of hops and use the 
`--payloads` arg to specify what message should be delivered to 
each of the specified hops. In the Lightning network, these 
messages would be the HTLC info to set up with the next hop.

```
go run ./cmd --user=alice build --hops="bob,charlie,dave" --payloads="message for bob, message for charlie, message for dave"
```

The above command will spit out an Onion that should be passed 
on to the next hop (in the example above, Bob).

### Peeling the Onion:

The onion from the previous command can now be passed to the specified hop:

```
go run ./cmd --user=bob parse --payload="<onion here>"
```

This will then spit out the next onion along with then hop that this onion 
should be sent to next. 

You can repeat this until a hop reports that it is the final hop. 

## Example 2: Onion with blinded path

For this example, let's assume this channel graph:

```
Alice <-> Bob <-> Charlie <-> Dave <-> Eve
```

And let's say that Eve wants to blind the last 2 hops. So to Alice, the 
graph will look more like this:

```
Alice <-> Bob <-> Charlie <-> B(Dave) <-> B(Eve)
```

Where `B(P)` means that the public key for node `P` is blinded to Alice. 
In this example, Charlie is the entry node. 

### Building the blinded path:

First, Eve needs to build the blinded path from C to E and specify the 
message that she wants to send each of the hops on that path. This can be 
done as follows:

```
go run ./cmd --user=eve build blindedRoute --hops="charlie,dave,eve" --payloads="hi charlie, hi dave, hi Me"
```

This will spit out all the info that Eve must give Alice so that Alice 
can construct the onion. The command will print all the info in an 
easy-to-read format along with the encoded format. Copy the encoded 
bytes so that we can pass it to Alice for the next step.

### Building the onion:

Just like in Example 1, Alice now constructs a route. However, she now only 
gets to pick the hops between herself and the entry node. She can specify a 
payload message for each hop along the whole route though. She also passes 
along the blinded route from eve (this is the part you copied from the 
previous step):

```
go run ./cmd --user=alice build onion --hops="bob,charlie" --payloads="bob from alice, charlie from alice, blinded hop 0 from alice, blinded hop 1 from alice" --blindedRoute="<blinded_route>"
```

This will spit out the Onion along with whom Alice should give this onion to. 
In this example, it is Bob. So we give this onion to Bob:

```
go run ./cmd --user=bob parse --payload="<onion>"
```

Repeat the above for Charlie. 
Since Charlie is the entry node to the blinded path, it will spit out a bit more info: It will
give you an onion, the node the pass the onion to _AND_ an ephemeral key that must also be passed to 
the next node. In our example, the next hop will be Dave, so our instruction to Dave will be:

```
go run ./cmd --user=dave parse --payload="<onion>" --ephemeral="<ephemeral>"
```

Repeat this step for Eve. Eve will be able to tell that she is the final hop.