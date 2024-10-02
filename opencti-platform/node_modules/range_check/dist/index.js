"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  displayIP: () => displayIP,
  inRange: () => inRange,
  isIP: () => isIP,
  isIPInRangeOrPrivate: () => isIPInRangeOrPrivate,
  isPrivateIP: () => isPrivateIP,
  isRange: () => isRange,
  isV4: () => isV4,
  isV6: () => isV6,
  searchIP: () => storeIP,
  storeIP: () => storeIP,
  version: () => version
});
module.exports = __toCommonJS(src_exports);
var import_ipaddr = __toESM(require("ipaddr.js"));
var import_ip6 = __toESM(require("ip6"));
function isIP(addr) {
  const ver = version(addr);
  return ver === 4 || ver === 6;
}
function version(addr) {
  try {
    const parse_addr = import_ipaddr.default.parse(addr);
    const kind = parse_addr.kind();
    if (kind === "ipv4") {
      if (import_ipaddr.default.IPv4.isValidFourPartDecimal(addr)) {
        return 4;
      } else {
        return 0;
      }
    } else if (kind === "ipv6") {
      return 6;
    } else {
      return 0;
    }
  } catch (err) {
    return 0;
  }
}
function isV4(addr) {
  return version(addr) === 4;
}
function isV6(addr) {
  return version(addr) === 6;
}
function isRange(range) {
  try {
    import_ipaddr.default.parseCIDR(range);
    return true;
  } catch (err) {
    return false;
  }
}
function inRange(addr, range) {
  if (typeof range === "string") {
    if (range.indexOf("/") !== -1) {
      try {
        const range_data = range.split("/");
        const parse_addr = import_ipaddr.default.parse(addr);
        const parse_range = import_ipaddr.default.parse(range_data[0]);
        return parse_addr.match(parse_range, range_data[1]);
      } catch (err) {
        return false;
      }
    } else {
      addr = isV6(addr) ? import_ip6.default.normalize(addr) : addr;
      range = isV6(range) ? import_ip6.default.normalize(range) : range;
      return isIP(range) && addr === range;
    }
  } else if (range && typeof range === "object") {
    for (const check_range in range) {
      if (inRange(addr, range[check_range]) === true) {
        return true;
      }
    }
    return false;
  } else {
    return false;
  }
}
function isPrivateIP(ip) {
  try {
    const addr = import_ipaddr.default.parse(ip);
    const kind = addr.kind();
    const range = addr.range();
    if (kind === "ipv4") {
      return range === "private" || range === "loopback" || ip === "127.0.0.1";
    } else if (kind === "ipv6") {
      return range === "uniqueLocal" || range === "loopback" || ip === "::1";
    }
    return false;
  } catch (err) {
    return false;
  }
}
function isIPInRangeOrPrivate(ip, options = { allowAnyPrivate: true }) {
  if (options.allowAnyPrivate !== false && isPrivateIP(ip)) {
    return true;
  }
  if (options.ranges) {
    return inRange(ip, options.ranges);
  }
  return false;
}
function storeIP(addr) {
  try {
    var parse_addr = import_ipaddr.default.parse(addr);
    var kind = parse_addr.kind();
    if (kind === "ipv4") {
      return addr;
    } else if (kind === "ipv6") {
      if (parse_addr.isIPv4MappedAddress()) {
        return parse_addr.toIPv4Address().toString();
      } else {
        return import_ip6.default.abbreviate(addr);
      }
    } else {
      return null;
    }
  } catch (err) {
    return null;
  }
}
function displayIP(addr) {
  try {
    var parse_addr = import_ipaddr.default.parse(addr);
    var kind = parse_addr.kind();
    if (kind === "ipv4") {
      return addr;
    } else if (kind === "ipv6") {
      if (parse_addr.isIPv4MappedAddress()) {
        return parse_addr.toIPv4Address().toString();
      } else {
        return import_ip6.default.normalize(addr);
      }
    } else {
      return "";
    }
  } catch (err) {
    return "";
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  displayIP,
  inRange,
  isIP,
  isIPInRangeOrPrivate,
  isPrivateIP,
  isRange,
  isV4,
  isV6,
  searchIP,
  storeIP,
  version
});
