# Bitbash

`***UNFINISHED***`

This is a system register decoding and visualization tool inspired by http://www.bradgoodman.com/bittool/.

## Definition language
```
name REG
size 64
[1:0] = ASD
if ASD == 0b11 {
	[3:2] = DSA
	if DSA == 0b0: "Description for 0b0"
}

```

Most register definitions are copied from https://github.com/rust-embedded/aarch64-cpu, big thanks to them.
