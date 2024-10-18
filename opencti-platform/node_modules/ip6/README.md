# ip6
IPv6 address helper utilities. <a href="https://ip6.sh">ip6.sh</a>

## Installation
### Module
`npm install ip6`

### Standalone
`npm install ip6 -g`

## Module Usage
### To `normalize` IPv6 addresses
```javascript
import ip6 from 'ip6';

console.log(ip6.normalize('2404:6800:4003:808::200e'));
// 2404:6800:4003:0808:0000:0000:0000:200e
console.log(ip6.normalize('2404:6800:4003:0808:0000:0000:0000:200e'));
// 2404:6800:4003:0808:0000:0000:0000:200e
console.log(ip6.normalize('2404:6800:4003:808::'));
// 2404:6800:4003:0808:0000:0000:0000:0000
console.log(ip6.normalize('2404:68::'));
// 2404:0068:0000:0000:0000:0000:0000:0000
console.log(ip6.normalize('2404:0068:0000:0000:0000:0000:0000:0000'));
// 2404:0068:0000:0000:0000:0000:0000:0000
console.log(ip6.normalize('2404:6800:4003:0808:0:0:0:200e'));
// 2404:6800:4003:0808:0000:0000:0000:200e
console.log(ip6.normalize('::1'));
// 0000:0000:0000:0000:0000:0000:0000:0001
```

### To `abbreviate` IPv6 addresses

```javascript
console.log(ip6.abbreviate('2001:0000:0111:0000:0011:0000:0001:0000'));
// 2001:0:111:0:11:0:1:0
console.log(ip6.abbreviate('2001:0001:0000:0001:0000:0000:0000:0001'));
// 2001:1:0:1::1
console.log(ip6.abbreviate('2001:0001:0000:0001:0000:0000:0000:0000'));
// 2001:1:0:1::
console.log(ip6.abbreviate('0000:0000:0000:0000:0000:0000:0000:0000'));
// ::
console.log(ip6.abbreviate('0000:0000:0000:0000:0000:0000:0000:0001'));
// ::1
console.log(ip6.abbreviate('2041:0000:140F:0000:0000:0000:875B:131B'));
// 2041:0:140F::875B:131B
console.log(ip6.abbreviate('2001:0001:0002:0003:0004:0005:0006:0007'));
// 2001:1:2:3:4:5:6:7
```

### To divide a `/64` subnet into 4 `/66` subnets
```javascript
let subnets = ip6.divideSubnet("2607:5300:60:1234::", 64, 66);
console.log(subnets);
/*
outputs:
[ '2607:5300:0060:1234:0000:0000:0000:0000',
  '2607:5300:0060:1234:4000:0000:0000:0000',
  '2607:5300:0060:1234:8000:0000:0000:0000',
  '2607:5300:0060:1234:c000:0000:0000:0000' ]
*/
```

### To divide a `/64` subnet into `/128` subnets, but limit to 8 addresses
```javascript
let subnets = ip6.divideSubnet("2607:5300:60:1234::", 64, 128, 8);
console.log(subnets);
/*
[ '2607:5300:0060:1234:0000:0000:0000:0000',
  '2607:5300:0060:1234:0000:0000:0000:0001',
  '2607:5300:0060:1234:0000:0000:0000:0002',
  '2607:5300:0060:1234:0000:0000:0000:0003',
  '2607:5300:0060:1234:0000:0000:0000:0004',
  '2607:5300:0060:1234:0000:0000:0000:0005',
  '2607:5300:0060:1234:0000:0000:0000:0006',
  '2607:5300:0060:1234:0000:0000:0000:0007' ]
*/
```

### To divide a `/64` subnet into `/128` subnets, but limit to 8 abbreviated addresses
```javascript
let subnets = ip6.divideSubnet("2607:5300:60:1234::", 64, 128, 8, true);
console.log(subnets);
/*
[ '2607:5300:60:1234::',
  '2607:5300:60:1234::1',
  '2607:5300:60:1234::2',
  '2607:5300:60:1234::3',
  '2607:5300:60:1234::4',
  '2607:5300:60:1234::5',
  '2607:5300:60:1234::6',
  '2607:5300:60:1234::7' ]
*/
```

### To generate 5 random `/128` from a `/48` (output in abbreviated mode):
```javascript
let r = ip6.randomSubnet("2607:5300:60::", 48, 128, 5, true);
console.log(r);
/*
[ '2607:5300:60:ba28:1acc:11ef:23a:770',
  '2607:5300:60:c1e:1f2:4b93:f2e6:bc31',
  '2607:5300:60:58b3:df4c:d91b:508f:b022',
  '2607:5300:60:fec3:4790:f791:ae5b:8675',
  '2607:5300:60:41b9:20a8:dd08:1c9e:7bc3' ]
*/
```

### To calculate the range and size of a `/64` subnet:
```javascript
let range = ip6.range("2607:5300:60:1234::", 64, 128);
console.log(range);
/*
{ start: '2607:5300:0060:1234:0000:0000:0000:0000',
  end: '2607:5300:0060:1234:ffff:ffff:ffff:ffff',
  size: 18446744073709552000 }
 */
```

### To calculate the range and size of a `/48` subnet divided into /56 subnets (output in abbreviated mode):
```javascript
let range = ip6.range("2607:5300:60::", 48, 56, true);
console.log(range);
/*
{ start: '2607:5300:60::',
  end: '2607:5300:60:ff00::',
  size: 256 }
 */
```

### To generate a PTR record for DNS zone file:
```javascript
let ptr = ip6.ptr("2607:5300:60:1234:cafe:babe:dead:beef", 64);
console.log(ptr);
// f.e.e.b.d.a.e.d.e.b.a.b.e.f.a.c
```

## Standalone Usage
### To normalize an IPv6 address:
```bash
ip6 -n 2001:db8::
2001:0db8:0000:0000:0000:0000:0000:0000
```

### To abbreviate an IPv6 address:
```bash
ip6 -a 2001:0db8:0000:0000:0000:0000:0000:0000
2001:db8::
```

### To divide a `/64` subnet into 4 `/66` subnets:
```bash
ip6 -d 2001:db8:: 64 66
2001:0db8:0000:0000:0000:0000:0000:0000
2001:0db8:0000:0000:4000:0000:0000:0000
2001:0db8:0000:0000:8000:0000:0000:0000
2001:0db8:0000:0000:c000:0000:0000:0000
```

### To divide a `/64` subnet into `/80` subnets, but outputs only 5 subnets:
```bash
ip6 -d 2001:db8:: 64 80 5
2001:0db8:0000:0000:0001:0000:0000:0000
2001:0db8:0000:0000:0002:0000:0000:0000
2001:0db8:0000:0000:0003:0000:0000:0000
2001:0db8:0000:0000:0004:0000:0000:0000
2001:0db8:0000:0000:0005:0000:0000:0000
```

### To divide a `/64` subnet into `/80` subnets, but outputs only 5 subnets in abbreviated mode:
```bash
ip6 -d -s 2001:db8:: 64 80 5
2001:db8:0:0:1::
2001:db8:0:0:2::
2001:db8:0:0:3::
2001:db8:0:0:4::
2001:db8:0:0:5::
```

### To generate 5 random `/56` subnets from a `/48` subnets:
```bash
ip6 -r -s 2607:5300:60:: 48 56 5
2607:5300:60:6300::
2607:5300:60:f300::
2607:5300:60:7000::
2607:5300:60:ce00::
2607:5300:60:9100::
```

### To calculate the range and size of a `/48` subnet divided into /56 subnets (output in abbreviated mode):
```bash
ip6 -R -s 2607:5300:60:: 48 56
{"start":"2607:5300:60::","end":"2607:5300:60:ff00::","size":256}
```

### To generate a PTR record for DNS zone file:
```bash
ip6 -p 2607:5300:60:1234:cafe:babe:dead:beef 64
f.e.e.b.d.a.e.d.e.b.a.b.e.f.a.c
```

## License
The MIT License (MIT)

Copyright (c) 2016 Qian Chen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
