import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as cache from '../../../../../src/database/cache';
import type { BasicStoreIdentifier } from '../../../../../src/types/store';
import type { StixBundle, StixObject } from '../../../../../src/types/stix-2-1-common';
import { PLAYBOOK_MATCHING_COMPONENT, PLAYBOOK_REDUCING_COMPONENT } from '../../../../../src/modules/playbook/playbook-components';
import type { ExecutorParameters } from '../../../../../src/modules/playbook/playbook-types';

describe('Playbook filtering components without filters in configuration', () => {
  const report = { id: 'report--f3e554eb-60f5-587c-9191-4f25e9ba9f32', type: 'report' } as unknown as StixObject;
  const bundle = { objects: [report] } as unknown as StixBundle;
  const buildParams = (component: string) => ({
    dataInstanceId: report.id,
    bundle,
    playbookNode: { id: 'node-id', name: component, configuration: {} },
  });

  beforeEach(() => {
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map());
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ id: 'settings-id' } as unknown as BasicStoreIdentifier);
  });

  it('should match everything with match knowledge component', async () => {
    const params = buildParams('match') as unknown as ExecutorParameters<any>;
    const result = await PLAYBOOK_MATCHING_COMPONENT.executor(params);
    expect(result.output_port).toEqual('out');
  });

  it('should keep everything with reduce knowledge component', async () => {
    const params = buildParams('reduce') as unknown as ExecutorParameters<any>;
    const result = await PLAYBOOK_REDUCING_COMPONENT.executor(params);
    expect(result.output_port).toEqual('out');
    expect(result.bundle.objects).toEqual([report]);
  });
});
