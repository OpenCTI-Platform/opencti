import { beforeEach, describe, expect, it, vi } from 'vitest';
import xtmOneClient from '../../../../src/modules/xtm/one/xtm-one-client';
import { availableComponents } from '../../../../src/modules/playbook/playbook-domain';
import * as ee from '../../../../src/enterprise-edition/ee';
import { testContext } from '../../../utils/testQuery';

const XTM_ONE_DEPENDENT_IDS = [
  'PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT',
  'PLAYBOOK_AI_AGENT_SEND_COMPONENT',
];

describe('availableComponents', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    // Skip the EE gate so the function returns instead of throwing.
    vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue(undefined);
  });

  it('should expose the AI-agent components when XTM One is configured', async () => {
    vi.spyOn(xtmOneClient, 'isConfigured').mockReturnValue(true);

    const components = await availableComponents(testContext);
    const componentIds = components.map((c) => c.id);

    for (const id of XTM_ONE_DEPENDENT_IDS) {
      expect(componentIds).toContain(id);
    }
  });

  it('should hide the AI-agent components when XTM One is not configured', async () => {
    vi.spyOn(xtmOneClient, 'isConfigured').mockReturnValue(false);

    const components = await availableComponents(testContext);
    const componentIds = components.map((c) => c.id);

    for (const id of XTM_ONE_DEPENDENT_IDS) {
      expect(componentIds).not.toContain(id);
    }
    // Sanity: non-XTM-One components are still listed (we did not accidentally
    // wipe the registry — pick a stable representative).
    expect(componentIds).toContain('PLAYBOOK_INTERNAL_MANUAL_TRIGGER');
  });
});
