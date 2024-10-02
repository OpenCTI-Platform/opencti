// import { describe, expect, it } from 'vitest';
// import { inRange as inRangeFromLib, isRange } from 'range_check';
// import ipaddr from 'ipaddr.js';
// import { ipv4List, ipv4RangeList, ipv6RangeList, sampleList } from './testList';
//
// const fullList = [...ipv4RangeList, ...ipv6RangeList, ...ipv4List];
// const bigList = [...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList, ...fullList];
//
// const ipv4RangeListSize = ipv4RangeList.length;
// const ipv6RangeListSize = ipv6RangeList.length;
// const fullListSize = fullList.length;
//
// const size1k = 1000;
// const size10k = 10000;
// const size100k = 100000;
// const size500k = 500000;
// const size1m = 1000000;
//
// const getIpAddrType = (range) => ipaddr.parse(range.split('/')[0]).kind();
// const isRange = (value) => value.indexOf('/') !== -1;
//
// const isInExclusionList = (ipToTest, list) => list.filter((item) => {
//   const parsedIpAddrToTest = ipaddr.parse(ipToTest);
//   const ipAddrToTestType = parsedIpAddrToTest.kind();
//
//   if (getIpAddrType(item) !== ipAddrToTestType) return false;
//   if (isRange(item)) return parsedIpAddrToTest.match(ipaddr.parseCIDR(item));
//   return ipToTest === item;
// });
//
// const isInExclusionList2 = (ipToTest, list) => {
//   const parsedIpAddrToTest = ipaddr.parse(ipToTest);
//   const ipAddrToTestType = parsedIpAddrToTest.kind();
//   const result = [];
//   for (let i = 0; i < list.length; i++) {
//     if (getIpAddrType(list[i]) === ipAddrToTestType) {
//       if (isRange(list[i]) && parsedIpAddrToTest.match(ipaddr.parseCIDR(list[i]))) result.push(list[i]);
//       if (ipToTest === list[i]) result.push(list[i]);
//     }
//   }
//   return result;
// };
//
// export const convertIpAddrToBinary = (ipToTest: string, list: string[]) => {
//   console.time();
//   const result = isInExclusionList(ipToTest, list);
//   console.log('result 2 : ', result);
//   console.timeEnd();
// };
//
// export const convertIpAddrToBinary2 = (ipToTest: string, list: string[]) => {
//   console.time();
//   const result = isInExclusionList2(ipToTest, list);
//   console.log('result 2 : ', result);
//   console.timeEnd();
// };
//
// const convertIpv6ToBinary = (ipv6, isR) => {
//   let test = ipv6.split(':');
//   const emptyFieldIndex = test.indexOf('');
//
//   if (isR) {
//     return ipv6.split(':').filter((t) => t !== '').map((t) => (t === '' ? '0' : t)).map((hex) => (parseInt(hex, 16).toString(2)).padStart(16, '0'));
//   }
//
//   if (emptyFieldIndex !== -1 && test.length < 8) {
//     test = [
//       ...test.slice(0, emptyFieldIndex + 1),
//       ...Array(8 - test.length).fill('0'),
//       ...test.slice(emptyFieldIndex + 1)
//     ];
//   }
//
//   return test.map((t) => (t === '' ? '0' : t)).map((hex) => (parseInt(hex, 16).toString(2)).padStart(16, '0'));
// };
//
// describe('teste', () => {
//   // it('test ipv4', () => {
//   //   const testrange = '75.126.0.0/16';
//   //   const testip = '75.126.95.138';
//   //   const aaa = testip.split('.').map((item) => parseInt(item, 10).toString(16)).join('.');
//   //   console.log('aaa : ', aaa);
//   //   // const parsedIpAddrToTest = ipaddr.parse(testip);
//   //   // const aze = ipaddr.parseCIDR(testrange);
//   //   // const qsd = parsedIpAddrToTest.match(aze);
//   //   // console.log('aze : ', aze);
//   //   // console.log('qsd : ', qsd);
//   //   //
//   //   // const splitted = testrange.split('/')[0];
//   //   // console.log('splitted : ', splitted);
//   //   // const wxc = ipaddr.parse(splitted);
//   //   // console.log('wxc : ', wxc);
//   //   // const byttes = wxc.toByteArray();
//   //   // console.log('wxc.toByteArray() : ', wxc.toByteArray());
//   //   // console.log('byttes : ', byttes);
//   // });
//
//   it('test ipv6 to binary', () => {
//     const qsd = '0010011000000100:1010100010000000:0000010000000000:0000000011010001:0000000000000000:0000000000000000:0000001111000000:1111000000000001';
//     const testip = '2604:a880:400:d1::3c0:f001';
//     const testip2 = '2604:a880:400::f001';
//     // const aze = testip.split(':').map((t) => (t === '' ? '0' : t)).map((hex) => {
//     //   return (parseInt(hex, 16).toString(2)).padStart(16, '0');
//     // });
//     // console.log('binary : ', aze);
//     convertIpv6ToBinary(testip2);
//     // convertIpv6ToBinary(testip);
//     // console.log('binary test : ', qsd.split(':'));
//     // const wxc = aze.join(':');
//     // console.log('wxc test : ', qsd === wxc);
//   });
//
//   // it('test ipv6', () => {
//   //   const testrange = '2604:a880:400::/48';
//   //   const testip = '2604:a880:400:d1::3c0:f001';
//   //   const range = testrange.split('/')[0];
//   //   const aze = testip.startsWith(range);
//   //   console.log('aze : ', aze);
//   // });
// });
// // describe('test', () => {
// //   // it('test exact match fullList', () => {
// //   //   console.time();
// //   //   const aze = fullList.filter((item) => item === '99.99.99.193');
// //   //   console.log('test exact match fullList');
// //   //   console.timeEnd();
// //   // });
// //   //
// //   // it('test exact match bigList', () => {
// //   //   console.time();
// //   //   const aze = bigList.filter((item) => item === '99.99.99.193');
// //   //   console.log('test exact match bigList');
// //   //   console.timeEnd();
// //   // });
// //   //
// //   // it('test ipaddr fullList for()', () => {
// //   //   convertIpAddrToBinary2('99.99.99.193', fullList);
// //   // });
// //   //
// //   // it('test ipaddr bigList for()', () => {
// //   //   convertIpAddrToBinary2('99.99.99.193', bigList);
// //   // });
// //   //
// //   // it('test ipaddr fullList filter', () => {
// //   //   convertIpAddrToBinary('99.99.99.193', fullList);
// //   // });
// //   //
// //   // it('test ipaddr bigList filter', () => {
// //   //   convertIpAddrToBinary('99.99.99.193', bigList);
// //   // });
// //
// //   it('test bigList with index of', () => {
// //     console.time();
// //     console.log('bigList : ', bigList.length);
// //
// //     const test = bigList.filter((item) => {
// //       const testRange = item.indexOf('/') !== -1;
// //       // const testRange = isRange(item);
// //       return testRange
// //         ? inRangeFromLib('99.99.99.193', item)
// //         : item === '99.99.99.193';
// //     });
// //
// //     console.log('test : ', test);
// //     console.log('test bigList');
// //     console.timeEnd();
// //   });
// //
// //   it('test bigList with lib', () => {
// //     console.time();
// //     console.log('bigList : ', bigList.length);
// //
// //     const test = bigList.filter((item) => {
// //       // const testRange = item.indexOf('/') !== -1;
// //       const testRange = isRange(item);
// //       return testRange
// //         ? inRangeFromLib('99.99.99.193', item)
// //         : item === '99.99.99.193';
// //     });
// //
// //     console.log('test : ', test);
// //     console.log('test bigList');
// //     console.timeEnd();
// //   });
// // });
