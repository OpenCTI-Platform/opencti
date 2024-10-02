declare function isIP(addr: string): boolean;
declare function version(addr: string): number;
declare function isV4(addr: string): boolean;
declare function isV6(addr: string): boolean;
declare function isRange(range: string): boolean;
declare function inRange(addr: string, range: string | string[]): boolean;
declare function isPrivateIP(ip: string): boolean;
declare function isIPInRangeOrPrivate(ip: string, options?: {
    ranges?: string[] | string;
    allowAnyPrivate?: boolean;
}): boolean;
declare function storeIP(addr: string): any;

declare function displayIP(addr: string): any;

export { displayIP, inRange, isIP, isIPInRangeOrPrivate, isPrivateIP, isRange, isV4, isV6, storeIP as searchIP, storeIP, version };
