import { describe, expect, it } from 'vitest';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { ruleApplyAsync, ruleRescanAsync } from '../../../src/intake/stix-import/operations-knowledge';

// pycti asks again until the platform reports the rule apply or rescan complete, without a bound:
// the port asks as pycti does, but gives up past a bound instead of holding the importer forever
const contextAnswering = (answers: (calls: number) => boolean) => {
  const errors: string[] = [];
  let calls = 0;
  const client = {
    query: async (document: string) => {
      calls += 1;
      // Past the bound, the loop is unbounded: fail instead of spinning (microtasks only, no timeout fires)
      if (calls > 1000) throw new Error('asked past the bound');
      const complete = answers(calls);
      return document.includes('rulesRescanAsync') ? { rulesRescanAsync: complete } : { ruleApplyAsync: complete };
    },
  };
  const context = createImportContext(client, { error: (message) => errors.push(message), warn: () => {} });
  return { context, errors, calls: () => calls };
};

describe('Rule apply and rescan: ask until complete, within a bound', () => {
  it('should ask again until the platform reports completion, as pycti', async () => {
    const apply = contextAnswering((calls) => calls === 3);
    await ruleApplyAsync(apply.context, 'element', 'rule', 'execution');
    expect(apply.calls()).toEqual(3);
    expect(apply.errors).toEqual([]);
    const rescan = contextAnswering((calls) => calls === 2);
    await ruleRescanAsync(rescan.context, 'element', 'execution');
    expect(rescan.calls()).toEqual(2);
  });
  it('should give up, with an error log, a rule that never completes', async () => {
    const apply = contextAnswering(() => false);
    await ruleApplyAsync(apply.context, 'element', 'rule', 'execution');
    expect(apply.calls()).toEqual(1000);
    expect(apply.errors).toEqual(['[stix_core_object] ruleApplyAsync not complete after 1000 attempts, given up']);
    const rescan = contextAnswering(() => false);
    await ruleRescanAsync(rescan.context, 'element', 'execution');
    expect(rescan.calls()).toEqual(1000);
  }, 10000);
});
