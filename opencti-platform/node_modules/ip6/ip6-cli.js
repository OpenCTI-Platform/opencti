#!/usr/bin/env node

import ip6 from './ip6.js';

import { createRequire } from "module";
const require = createRequire(import.meta.url);

let pjson = require('./package.json');

(function () {
   'use strict';

   let args = function () {
      let ret = [];
      process.argv.forEach(function (val, index, array) {
         if (index >= 2) {
            ret.push(val);
         }
      });
      return ret;
   };
   let input = args();

   if (input.length === 0) {
      console.log('ip6 version: ', pjson.version);
      console.log('Usage:');
      console.log('   ip6 -v, --version           to show version information.');
      console.log('   ip6 -n, --normalize addr    to normalize an IPv6 address.');
      console.log('   ip6 -a, --abbreviate addr   to abbreviate an IPv6 address.');
      console.log('   ip6 -d, --divide [-s, --short] subnet mask new_mask [limit] \n        to divide an IPv6 subnet into smaller subnets.');
      console.log('   ip6 -r, --random [-s, --short] subnet mask new_mask [limit] \n        to generate random addresses/subnets from an IPv6 subnet.');
      console.log('   ip6 -R, --range [-s, --short] subnet mask new_mask \n        to calculate the range and size of an IPv6 subnet.');
      console.log('   ip6 -p, --ptr addr mask   to generate PTR record for DNS zone file.');
      console.log();
      console.log('Examples:');
      console.log('   To normalize an IPv6 address:');
      console.log('   ip6 -n 2001:db8::');
      console.log('   2001:0db8:0000:0000:0000:0000:0000:0000');
      console.log();
      console.log('   To abbreviate an IPv6 address:');
      console.log('   ip6 -a 2001:0db8:0000:0000:0000:0000:0000:0000');
      console.log('   2001:db8::');
      console.log();
      console.log('   To divide a /64 subnet into 4 /66 subnets:');
      console.log('   ip6 -d 2001:db8:: 64 66');
      console.log('   2001:0db8:0000:0000:0000:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:4000:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:8000:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:c000:0000:0000:0000');
      console.log();
      console.log('   To divide a /64 subnet into /80 subnets, but outputs only 5 subnets:');
      console.log('   ip6 -d 2001:db8:: 64 80 5');
      console.log('   2001:0db8:0000:0000:0000:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:0001:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:0002:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:0003:0000:0000:0000');
      console.log('   2001:0db8:0000:0000:0004:0000:0000:0000');
      console.log();
      console.log('   To divide a /64 subnet into /80 subnets, but outputs only 5 subnets in abbreviated mode:');
      console.log('   ip6 -d -s 2001:db8:: 64 80 5');
      console.log('   2001:db8::');
      console.log('   2001:db8:0:0:1::');
      console.log('   2001:db8:0:0:2::');
      console.log('   2001:db8:0:0:3::');
      console.log('   2001:db8:0:0:4::');
      console.log();
      console.log('   To generate 5 random /56 subnets from a /48 subnets:');
      console.log('   ip6 -r -s 2607:5300:60:: 48 56 5');
      console.log('   2607:5300:60:f00::');
      console.log('   2607:5300:60:3900::');
      console.log('   2607:5300:60:5c00::');
      console.log('   2607:5300:60:a800::');
      console.log('   2607:5300:60:e00::');
      console.log();
      console.log('   To calculate the range and size of a /64 subnet divided into /120 subnets:');
      console.log('   ip6 -R -s 2001:db8:: 64 80');
      console.log('   {"start":"2001:db8::","end":"2001:db8::ffff:ffff:ffff:ff00","size"::65536}');
      console.log();
      console.log('   To generate a PTR record for DNS zone file:');
      console.log('   ip6 -p 2607:5300:60:1234:cafe:babe:dead:beef 64');
      console.log('   f.e.e.b.d.a.e.d.e.b.a.b.e.f.a.c');
   } else if (input[0] === '-v' || input[0] === '--version') {
      console.log('ip6 version: ', pjson.version);
   } else if (input[0] === '-n' || input[0] === '--normalize') {
      try {
         const output = ip6.normalize(input[1]);
         console.log(output);
      } catch (e) {
         console.error(e.message);
      }
   } else if (input[0] === '-a' || input[0] === '--abbreviate') {
      try {
         const output = ip6.abbreviate(input[1]);
         console.log(output);
      } catch (e) {
         console.error(e.message);
      }
   } else if (input.includes('-d') || input.includes('--divide')) {
      let abbr = false;
      if (input.includes('-s') || input.includes('--short')) {
         abbr = true;
      }
      try {
         if (abbr) {
            const output = ip6.divideSubnet(input[2], input[3], input[4], input[5], true);
            for (let subnet of output) {
               console.log(subnet);
            }
         } else {
            const output = ip6.divideSubnet(input[1], input[2], input[3], input[4]);
            for (let subnet of output) {
               console.log(subnet);
            }
         }
      } catch (e) {
         console.error(e.message);
      }
   } else if (input.includes('-r') || input.includes('--random')) {
      let abbr = false;
      if (input.includes('-s') || input.includes('--short')) {
         abbr = true;
      }
      try {
         if (abbr) {
            const output = ip6.randomSubnet(input[2], input[3], input[4], input[5], true);
            for (let subnet of output) {
               console.log(subnet);
            }
         } else {
            const output = ip6.randomSubnet(input[1], input[2], input[3], input[4]);
            for (let subnet of output) {
               console.log(subnet);
            }
         }
      } catch (e) {
         console.error(e.message);
      }
   } else if (input.includes('-R') || input.includes('--range')) {
      let abbr = false;
      if (input.includes('-s') || input.includes('--short')) {
         abbr = true;
      }
      try {
         if (abbr) {
            const output = ip6.range(input[2], input[3], input[4], true);
            console.log(JSON.stringify(output));
         } else {
            const output = ip6.range(input[1], input[2], input[3]);
            console.log(JSON.stringify(output));
         }
      } catch (e) {
         console.error(e.message);
      }
   } else if (input[0] === '-p' || input[0] === '--ptr') {
      try {
         const output = ip6.ptr(input[1], input[2]);
         console.log(output);
      } catch (e) {
         console.error(e.message);
      }
   }
})();