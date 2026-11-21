import { afterEach, describe, expect, it, vi } from 'vitest';
import nconf from 'nconf';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  fullEntitiesOrRelationsList: vi.fn(),
  loadEntity: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  getRedisVersion: vi.fn(),
  notify: vi.fn(),
  setEditContext: vi.fn(),
}));
vi.mock('../../../src/database/cluster-module', () => ({ getClusterInformation: vi.fn() }));
vi.mock('../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../src/modules/theme/theme-domain', () => ({ findById: vi.fn() }));
vi.mock('../../../src/modules/xtm/one/xtm-one', () => ({
  getXtmOneRegistrationVersion: vi.fn(),
  refreshXtmLicenseProof: vi.fn(),
}));

const { getOpenCrqUrl } = await import('../../../src/domain/settings');

const setXtm = (key: string, value: string) => nconf.set(`xtm:${key}`, value);

describe('getOpenCrqUrl, the OpenCRQ instance of the product switcher', () => {
  afterEach(() => {
    setXtm('opencrq_url', '');
    setXtm('opengrc_url', '');
  });

  it('is empty when no OpenCRQ URL is configured', () => {
    expect(getOpenCrqUrl()).toBe('');
  });

  it('reads XTM__OPENCRQ_URL', () => {
    setXtm('opencrq_url', 'https://opencrq.example.com');
    expect(getOpenCrqUrl()).toBe('https://opencrq.example.com');
  });

  it('falls back to the deprecated XTM__OPENGRC_URL', () => {
    setXtm('opengrc_url', 'https://opengrc.example.com');
    expect(getOpenCrqUrl()).toBe('https://opengrc.example.com');
  });

  it('prefers XTM__OPENCRQ_URL over the deprecated XTM__OPENGRC_URL', () => {
    setXtm('opencrq_url', 'https://opencrq.example.com');
    setXtm('opengrc_url', 'https://opengrc.example.com');
    expect(getOpenCrqUrl()).toBe('https://opencrq.example.com');
  });
});
