# Ret Arm64 MMU page table decoder

***UNFINISHED***

This is a work in progress tool that will use the [FileReader](https://developer.mozilla.org/en-US/docs/Web/API/FileReader) API to decode Arm64 MMU translation tables and create
a nice looking memory map that can be shared with a URL.

## JSON Prototype:
- A format for a memory table in JSON that can be used across arm32/arm64
```
{
name: "My Memory Table",
granule_size: 4096,
sections:
[
	{
		address: 0x0,
		size: 0x100000,
		output_address: 0x0,
		attribute: 0,
		cache_attribute: 0,

		mair_value: 0xa5,
		xn: 0,
		pxn: 53

		// TODO: Blocks may be joined together into a section if they are identical.
		page_level: 1,
		block_location: 0xa0000000,
		block_descriptor: [0, 0, 0, 0, 0, 0, 0, 0],
	},
	...
]
}
```

## Web Interface
Use web APIs to get equivalent to fopen/fseek/fread
- Use FileReader
- readAsArrayBuffer
- .slice(0, 100)
- Allow additional section notes to be added by user
  - MMU devices
- Share memory map as URL

*Examples:*  
- https://wiki.osdev.org/Memory_Map_(x86)
- https://i0.wp.com/semiengineering.com/wp-content/uploads/Arteris_Where-Do-Memory-Maps-Come-From-fig1.png?fit=572%2C493&ssl=1
- https://i.ytimg.com/vi/aT5XMOrid7Y/maxresdefault.jpg
