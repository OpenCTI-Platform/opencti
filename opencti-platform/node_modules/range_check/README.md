# Range Check v3.1.0
[![npm version](https://badge.fury.io/js/range_check.svg)](https://badge.fury.io/js/range_check) &nbsp; [![Build Status](https://travis-ci.org/keverw/range_check.svg?branch=master)](https://travis-ci.org/keverw/range_check)

This is a simple module to validate IP address, check IP address version, check if IP is within a range.

This started out as `range_check` but it does much more than just checking ranges but since it's already got a large amount of downloads (37,115 downloads in the last month as of this writing) I'll keep the name the same even though I kinda want to change it to something better.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Install](#install)
- [IP Functions](#ip-functions)
  - [Check if IP is valid](#check-if-ip-is-valid)
  - [Check IP version](#check-ip-version)
    - [Version](#version)
    - [isV4](#isv4)
    - [isV6](#isv6)
- [Range Functions](#range-functions)
  - [Check if range is valid](#check-if-range-is-valid)
  - [Check if IP is within range](#check-if-ip-is-within-range)
  - [Check if IP is private](#check-if-ip-is-private)
  - [Check if IP is in range or private](#check-if-ip-is-in-range-or-private)
  - [storeIP](#storeip)
  - [searchIP](#searchip)
  - [displayIP](#displayip)
- [Contributing](#contributing)
- [Dependencies](#dependencies)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Install

`npm install range_check` or `yarn add range_check`

You can then import the functions as needed or require the entire `range_check` package depending on your own projects configuration.

## IP Functions
### Check if IP is valid

```typescript
console.log(isIP('10.0.1.5')); //returns true or false
```

### Check IP version
#### Version
```typescript
console.log(version('10.0.1.5')); //returns 4
console.log(version('2001:4860:8006::62')); //returns 6
console.log(version('foo')); //returns 0 as invalid IP address
```

#### isV4
```typescript
console.log(isV4('10.0.1.5')); //true
console.log(isV4('foo')); //false
console.log(isV4('123::123')); //false
```

#### isV6
```typescript
console.log(isV6('123::123')); //true
console.log(isV6('foo')); //false
console.log(isV6('10.0.1.5')); //false
```

## Range Functions

### Check if range is valid

You can use isRange if you want to validate an entire range.

```typescript
console.log(isRange('2001:db8::/32')); //true
console.log(isRange('10.0.0.0/8')); // true
console.log(isRange('qwerty')); // false

```

### Check if IP is within range
```typescript
console.log(inRange('10.0.1.5', '10.0.0.0/8')); //returns true

console.log(inRange('192.0.1.5', '10.0.0.0/8')); //returns false

console.log(inRange('2001:db8:1234::1', '2001:db8::/32')); //returns true
```

You can also give a list of ranges

```typescript
console.log(inRange('192.168.1.1', ['10.0.0.0/8', '192.0.0.0/8'])); //returns true

```

### Check if IP is private
```typescript
console.log(isPrivateIP('10.0.0.1')); //returns true
console.log(isPrivateIP('192.168.1.1')); //returns true
console.log(isPrivateIP('172.16.0.1')); //returns true
console.log(isPrivateIP('8.8.8.8')); //returns false
console.log(isPrivateIP('fd00::1')); //returns true (IPv6 ULA)
console.log(isPrivateIP('2001:db8::1')); //returns false
```

This function checks if an IP address is private. It returns true for:
- IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- IPv4 loopback addresses (127.0.0.0/8)
- IPv6 unique local addresses (fd00::/8)
- IPv6 loopback address (::1)

### Check if IP is in range or private
```typescript
console.log(isIPInRangeOrPrivate('192.168.1.1')); // returns true (private IP)
console.log(isIPInRangeOrPrivate('8.8.8.8')); // returns false (public IP, no range specified)
console.log(isIPInRangeOrPrivate('8.8.8.8', { ranges: '8.8.8.0/24' })); // returns true
console.log(isIPInRangeOrPrivate('10.0.0.1', { allowAnyPrivate: false, ranges: '8.8.8.0/24' })); // returns false
```

This function checks if an IP address is either within a specified range or is a private IP. It's particularly useful for scenarios where you need to determine if a request is coming from a local server or a specific set of allowed IPs.

Options:
- `ranges`: A string or array of strings representing IP ranges to check against.
- `allowAnyPrivate`: Boolean to determine if any private IP should be allowed. Defaults to true.

If no options are provided, the function will return true for any private IP and false for public IPs.

Use case example: This function can be used in server configurations to easily allow local calls or calls from specific IP ranges, while blocking others. For instance, it can be used in middleware for setting trace IDs. This allows you to automatically set trace IDs for requests from private networks or specific IP ranges, which can be useful for debugging and tracking requests across microservices in a distributed system.

### storeIP
This function is useful to get a consistent IP address such for storing it in a database or when searching in a database after being stored using this. So if a V6 address was sent compacted or not, or if you searched by either version this function would make sure you get a consistent IP address for both versions. Also the possibly of saving a few bytes.

If an V6 addressed is mapped as v4 is given it will convert it to V4, If any other V6 address is given it is __abbreviated__ and plain V4 addresses are left alone. Returns null if a invalid IP

```typescript
console.log(storeIP('foo')); //null
console.log(storeIP('::ffff:127.0.0.1')); //127.0.0.1
console.log(storeIP('2001:0000:0111:0000:0011:0000:0001:0000')); //2001:0:111:0:11:0:1:0
console.log(storeIP('2001:0001:0000:0001:0000:0000:0000:0000')); //2001:1:0:1::
console.log(storeIP('0000:0000:0000:0000:0000:0000:0000:0000')); //::
console.log(storeIP('0000:0000:0000:0000:0000:0000:0000:0001')); //::1
console.log(storeIP('2041:0000:140F:0000:0000:0000:875B:131B')); //2041:0:140F::875B:131B
console.log(storeIP('2001:0001:0002:0003:0004:0005:0006:0007')); //2001:1:2:3:4:5:6:7
console.log(storeIP('127.0.0.1')); //127.0.0.1
```

### searchIP
Same function as `storeIP`, just a clearer name when you are using it for search instead

### displayIP
This function is useful for displaying IP addresses, such as after grabbing it back from the database when using `storeIP`

If an V6 addressed mapped as v4 is given it will convert it to V4, If any other V6 address is given it is __normalized__ into the longer version and plain V4 addresses are left alone. Returns a empty string if a invalid IP

```typescript
console.log(displayIP(null)); // ''
console.log(displayIP('::ffff:127.0.0.1')); //'127.0.0.1'
console.log(displayIP('2001:0:111:0:11:0:1:0')); //'2001:0000:0111:0000:0011:0000:0001:0000'
console.log(displayIP('2001:1:0:1::')); //'2001:0001:0000:0001:0000:0000:0000:0000'
console.log(displayIP('::')); //'0000:0000:0000:0000:0000:0000:0000:0000'
console.log(displayIP('::1')); //'0000:0000:0000:0000:0000:0000:0000:0001'
console.log(displayIP('2041:0:140F::875B:131B')); //'2041:0000:140F:0000:0000:0000:875B:131B'
console.log(displayIP('2001:1:2:3:4:5:6:7')); //'2001:0001:0002:0003:0004:0005:0006:0007'
console.log(displayIP('127.0.0.1')); //'127.0.0.1'

```

## Contributing

This project is using this starter library [bun-lib-starter](https://github.com/maxam2017/bun-lib-starter/tree/main)
Currently to use NPM to publish, must have that installed with Node, along side `Bun`

```sh
cd into the repo

pre-commit install

bun install
```

 - `bun run test`: Run test suite
 - `bun run build`: Generate bundles and typings
 - `bun run format`: Format source files, readme, etc


## Dependencies
* ipaddr.js - [https://github.com/whitequark/ipaddr.js](https://github.com/whitequark/ipaddr.js)
* ip6 - [https://github.com/elgs/ip6](https://github.com/elgs/ip6)