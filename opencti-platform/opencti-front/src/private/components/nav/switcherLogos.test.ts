import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The product switcher logos are ONE set, byte-identical in OpenCTI, OpenAEV and OpenCRQ: wordmark
 * and mark #0FBCFF on dark and #0015A8 on light, 164 units wide. The table is the same in the three
 * repositories; a logo changes in the three products together, with this table.
 */
const CANONICAL: Record<string, string> = {
  'logo_open_aev_dark.svg': 'c7b72800abc678c749861c0e8cf7db723c19513c2200c328795c189ca6906d71',
  'logo_open_aev_light.svg': '4a5cbdf51604e1198dce2a4b233487f6c5780731eef8c6f7c5d9746e9ab2cd80',
  'logo_open_crq_dark.svg': '8eed6b19678ee35173bf505935df4d7dbae9c0287b71c0ebbb6fa99ca7f388a9',
  'logo_open_crq_light.svg': 'f76730b9781ad86ce9a5a5cc6741c66b14b341963203028ce92b440dc539e9fa',
  'logo_open_cti_dark.svg': '0e6eaa2c3b62745f43d6e3681eede1b0e5cfbdf3c50635601a5c0c2a89e6dd40',
  'logo_open_cti_light.svg': 'af6b0a108e778db0c930b996233aa06f743985156184fab789ca44c432dc224e',
  'logo_xtm_hub_dark.svg': '24770f0fa34eebe8b58aeb6c6bd40f5e8cf066cbe455529d887108d8d13e9e8b',
  'logo_xtm_hub_light.svg': '49d77f9fe4d731a27350a3c97b2f6229c947409f8ff156e3e24607b8b65ae02f',
};

// Local file name -> canonical name.
const LOCAL: Record<string, string> = {
  'logo_open_aev_dark.svg': 'logo_open_aev_dark.svg',
  'logo_open_aev_light.svg': 'logo_open_aev_light.svg',
  'logo_open_crq_dark.svg': 'logo_open_crq_dark.svg',
  'logo_open_crq_light.svg': 'logo_open_crq_light.svg',
  'logo_xtm_hub_dark.svg': 'logo_xtm_hub_dark.svg',
  'logo_xtm_hub_light.svg': 'logo_xtm_hub_light.svg',
};

const IMAGES = resolve('src/static/images');
const sha256 = (file: string) => createHash('sha256').update(readFileSync(resolve(IMAGES, file))).digest('hex');

describe('product switcher logos', () => {
  it('ships every switcher logo byte-identical to the canonical set', () => {
    for (const [file, canonical] of Object.entries(LOCAL)) {
      expect([file, sha256(file)]).toEqual([file, CANONICAL[canonical]]);
    }
  });
});
