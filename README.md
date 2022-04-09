# Onion

- Repo for playing around with onion wrapping and peeling.
- Onion works as is stated in Lightning Bolt 4.
- Tis very rough and not at all pretty.

## Example: 

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
go run ./cmd --user=bob parse --payload=<onion here>"
```

This will then spit out the next onion along with then hop that this onion 
should be sent to next. 

You can repeat this until a hop reports that it is the final hop. 