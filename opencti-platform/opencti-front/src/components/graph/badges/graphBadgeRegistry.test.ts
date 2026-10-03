import { afterEach, describe, expect, it } from 'vitest';
import { badgesOfNode, graphBadgeProviders, registerGraphBadgeProvider } from './graphBadgeRegistry';
import { confidenceBadgeProvider, inferredBadgeProvider, markingBadgeProvider } from './builtinGraphBadges';
import { graphNodeActionsFor, registerGraphNodeAction } from './graphNodeActionRegistry';
import { graphNode } from '../../../utils/tests/graphTestData';
import { NO_MARKING_ID } from '../utils/useGraphParser';
import { LOW_CONFIDENCE_THRESHOLD } from '../utils/graphPainting';

const helpers = { t_i18n: (message: string) => `t:${message}` };
const cleanups: (() => void)[] = [];
afterEach(() => {
  cleanups.splice(0).forEach((cleanup) => cleanup());
});

describe('graph badge registry', () => {
  it('orders providers and lets one be removed', () => {
    cleanups.push(registerGraphBadgeProvider({ id: 'z-late', order: 500, badgesFor: () => [] }));
    const remove = registerGraphBadgeProvider({ id: 'a-early', order: 1, badgesFor: () => [] });
    const ids = graphBadgeProviders().map((p) => p.id);
    expect(ids.indexOf('a-early')).toBeLessThan(ids.indexOf('z-late'));
    remove();
    expect(graphBadgeProviders().map((p) => p.id)).not.toContain('a-early');
  });

  it('replaces a provider registered again under the same id', () => {
    cleanups.push(registerGraphBadgeProvider({ id: 'pulse', badgesFor: () => [{ key: 'v1', tone: 'info', label: 'v1' }] }));
    cleanups.push(registerGraphBadgeProvider({ id: 'pulse', badgesFor: () => [{ key: 'v2', tone: 'info', label: 'v2' }] }));
    const keys = badgesOfNode(graphNode(), helpers).map((b) => b.key);
    expect(keys).toContain('v2');
    expect(keys).not.toContain('v1');
  });

  it('skips a provider that throws instead of breaking the graph', () => {
    cleanups.push(registerGraphBadgeProvider({
      id: 'broken',
      badgesFor: () => {
        throw new Error('field missing');
      },
    }));
    expect(() => badgesOfNode(graphNode(), helpers)).not.toThrow();
  });

  it('reads soft-checked fields from the raw object', () => {
    cleanups.push(registerGraphBadgeProvider({
      id: 'soft-check',
      badgesFor: (node) => {
        const verdict = (node.raw as { hunt_verdict?: string } | undefined)?.hunt_verdict;
        return verdict ? [{ key: 'hunt', tone: 'error', label: verdict }] : [];
      },
    }));
    expect(badgesOfNode(graphNode(), helpers).find((b) => b.key === 'hunt')).toBeUndefined();
    const raw = { hunt_verdict: 'Malicious' } as unknown as NonNullable<ReturnType<typeof graphNode>['raw']>;
    expect(badgesOfNode(graphNode({ raw }), helpers).find((b) => b.key === 'hunt')?.label).toBe('Malicious');
  });
});

describe('built-in badges', () => {
  it('shows one dot per marking in its colour, never for unmarked elements', () => {
    const marked = graphNode({ markedBy: [{ id: 'tlp', definition: 'TLP:GREEN', x_opencti_color: '#2e7d32' }] });
    expect(markingBadgeProvider.badgesFor(marked, helpers)).toEqual([
      { key: 'marking-tlp', tone: 'neutral', color: '#2e7d32', label: 'TLP:GREEN' },
    ]);
    const unmarked = graphNode({ markedBy: [{ id: NO_MARKING_ID, definition: 'None' }] });
    expect(markingBadgeProvider.badgesFor(unmarked, helpers)).toEqual([]);
  });

  it('flags a low confidence only', () => {
    expect(confidenceBadgeProvider.badgesFor(graphNode({ confidence: LOW_CONFIDENCE_THRESHOLD }), helpers)).toEqual([]);
    expect(confidenceBadgeProvider.badgesFor(graphNode({ confidence: null }), helpers)).toEqual([]);
    const [badge] = confidenceBadgeProvider.badgesFor(graphNode({ confidence: 10 }), helpers);
    expect(badge).toMatchObject({ tone: 'warning', value: 10, label: 't:Low confidence (10)' });
  });

  it('flags inferred elements', () => {
    expect(inferredBadgeProvider.badgesFor(graphNode({ isNestedInferred: true }), helpers)).toHaveLength(1);
    expect(inferredBadgeProvider.badgesFor(graphNode(), helpers)).toEqual([]);
  });
});

describe('graph node action registry', () => {
  it('lists the actions available for a node on a surface, skipping failing checks', () => {
    const icon = () => null;
    cleanups.push(registerGraphNodeAction({
      id: 'hunt', icon, label: () => 'Run a hunt', isAvailable: (node, context) => node.entity_type === 'Malware' && context === 'investigation',
    }));
    cleanups.push(registerGraphNodeAction({
      id: 'broken',
      icon,
      label: () => 'Broken',
      isAvailable: () => {
        throw new Error('soft check failed');
      },
    }));
    expect(graphNodeActionsFor(graphNode(), 'investigation').map((a) => a.id)).toEqual(['hunt']);
    expect(graphNodeActionsFor(graphNode(), undefined)).toEqual([]);
  });
});
