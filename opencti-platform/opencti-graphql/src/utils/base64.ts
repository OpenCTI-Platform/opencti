import { fromBase64, toBase64 } from '../database/utils';

export const toB64 = (data: unknown): string | undefined => toBase64(JSON.stringify(data));
export const fromB64 = <T = any>(data?: string): T | undefined => JSON.parse(fromBase64(data) || '{}');
