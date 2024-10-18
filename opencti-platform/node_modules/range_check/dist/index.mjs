// src/index.ts
import ipaddr from "ipaddr.js";
import ip6 from "ip6";
function isIP(addr) {
  const ver = version(addr);
  return ver === 4 || ver === 6;
}
function version(addr) {
  try {
    const parse_addr = ipaddr.parse(addr);
    const kind = parse_addr.kind();
    if (kind === "ipv4") {
      if (ipaddr.IPv4.isValidFourPartDecimal(addr)) {
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
    ipaddr.parseCIDR(range);
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
        const parse_addr = ipaddr.parse(addr);
        const parse_range = ipaddr.parse(range_data[0]);
        return parse_addr.match(parse_range, range_data[1]);
      } catch (err) {
        return false;
      }
    } else {
      addr = isV6(addr) ? ip6.normalize(addr) : addr;
      range = isV6(range) ? ip6.normalize(range) : range;
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
    const addr = ipaddr.parse(ip);
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
    var parse_addr = ipaddr.parse(addr);
    var kind = parse_addr.kind();
    if (kind === "ipv4") {
      return addr;
    } else if (kind === "ipv6") {
      if (parse_addr.isIPv4MappedAddress()) {
        return parse_addr.toIPv4Address().toString();
      } else {
        return ip6.abbreviate(addr);
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
    var parse_addr = ipaddr.parse(addr);
    var kind = parse_addr.kind();
    if (kind === "ipv4") {
      return addr;
    } else if (kind === "ipv6") {
      if (parse_addr.isIPv4MappedAddress()) {
        return parse_addr.toIPv4Address().toString();
      } else {
        return ip6.normalize(addr);
      }
    } else {
      return "";
    }
  } catch (err) {
    return "";
  }
}
export {
  displayIP,
  inRange,
  isIP,
  isIPInRangeOrPrivate,
  isPrivateIP,
  isRange,
  isV4,
  isV6,
  storeIP as searchIP,
  storeIP,
  version
};
