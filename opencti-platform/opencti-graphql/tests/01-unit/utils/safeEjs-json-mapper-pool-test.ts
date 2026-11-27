import { describe, expect, it } from 'vitest';
import { safeRender } from '../../../src/utils/safeEjs.client';
import { registerSafeEjsHostCall } from '../../../src/utils/safeEjs.pool';

let blockNextCall = 0;
// Stand-in for the Python STIX pattern builder, which only runs on the main thread
registerSafeEjsHostCall('patternFromValue', (k, v) => {
  if (blockNextCall > 0) {
    const end = Date.now() + blockNextCall;
    blockNextCall = 0;
    while (Date.now() < end) {
      // keep the main thread busy
    }
  }
  if (k === 'boom') {
    throw new Error('pattern failure');
  }
  return `${JSON.stringify(k)}=${JSON.stringify(v)}`;
});

const OPTIONS = { delimiter: '?', async: true, maxExecutedStatementCount: 10000, maxExecutionDuration: 5000, timeout: 5000, useJsonMapperHelpers: true };
const render = (formula: string, data: Record<string, unknown> = {}, options = {}) => safeRender(`<?- ${formula} ?>`, data, { ...OPTIONS, ...options });

describe('JSON mapper formulas rendered in the worker pool', () => {
  it('should call patternFromValue on the main thread through a host call', async () => {
    expect(await render('patternFromValue("ipv4-addr", ip)', { ip: '1.2.3.4' })).toEqual('"ipv4-addr"="1.2.3.4"');
  });

  it('should keep the type of the values passed to patternFromValue', async () => {
    expect(await render('patternFromValue("autonomous-system", asn)', { asn: 42 })).toEqual('"autonomous-system"=42');
    expect(await render('patternFromValue("ipv4-addr", ips)', { ips: ['1.1.1.1', '2.2.2.2'] })).toEqual('"ipv4-addr"=["1.1.1.1","2.2.2.2"]');
    expect(await render('patternFromValue("ipv4-addr", missing)', { missing: undefined })).toEqual('"ipv4-addr"=null');
  });

  it('should report a host call failure to the template', async () => {
    expect(await render('(() => { try { return patternFromValue("boom", "x"); } catch (e) { return e.message; } })()')).toEqual('pattern failure');
  });

  it('should run extractWithRegexp and decisionMatrix in the worker', async () => {
    expect(await render('extractWithRegexp("(.*)( - )([A-Z][0-9]{1,})", 1, name)', { name: 'APT - G0007' })).toEqual('APT');
    expect(await render('decisionMatrix(level, 50, [{ value: "high", result: 90 }])', { level: 'high' })).toEqual('90');
  });

  it('should chain several host calls in one formula', async () => {
    expect(await render('[1, 2, 3].map((i) => patternFromValue("n", i)).join(" OR ")'))
      .toEqual('"n"=1 OR "n"=2 OR "n"=3');
  });

  it('should not reach the main thread realm through a helper', async () => {
    await expect(render('(({ "constructor": F }) => F)(patternFromValue)')).rejects.toThrow();
    expect(await render('typeof patternFromValue.call === typeof (() => 1).call')).toEqual('true');
  });

  it('should stop an endless formula with the worker timeout instead of blocking the API process', async () => {
    const started = Date.now();
    await expect(render('(() => { for (;;); })()', {}, { maxExecutedStatementCount: 0, maxExecutionDuration: 0, timeout: 1000 }))
      .rejects.toThrow(/timeout|exceeded/i);
    expect(Date.now() - started).toBeLessThan(4000);
  });

  it('should never give a late host call reply to the next call', async () => {
    blockNextCall = 5500;
    await expect(render('patternFromValue("a", "first")', {}, { maxExecutionDuration: 0, timeout: 20000 })).rejects.toThrow(/timed out/);
    expect(await render('patternFromValue("b", "second")', {}, { maxExecutionDuration: 0, timeout: 20000 })).toEqual('"b"="second"');
  }, 30000);
});
