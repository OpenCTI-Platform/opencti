import { afterEach, describe, expect, it } from 'vitest';
import { badgesOfNode, drawnBadges, graphBadgeProviders, MAX_DRAWN_BADGES, registerGraphBadgeProvider } from './graphBadgeRegistry';
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
    expect(keys).toContain('pulse:v2');
    expect(keys).not.toContain('pulse:v1');
  });

  it('keeps apart two providers using the same key', () => {
    cleanups.push(registerGraphBadgeProvider({ id: 'hunts', badgesFor: () => [{ key: 'warning', tone: 'warning', label: 'Hunt' }] }));
    cleanups.push(registerGraphBadgeProvider({ id: 'curation', badgesFor: () => [{ key: 'warning', tone: 'warning', label: 'Curation' }] }));
    const keys = badgesOfNode(graphNode(), helpers).map((b) => b.key);
    expect(keys).toEqual(expect.arrayContaining(['hunts:warning', 'curation:warning']));
    expect(new Set(keys).size).toBe(keys.length);
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
    expect(badgesOfNode(graphNode(), helpers).find((b) => b.key === 'soft-check:hunt')).toBeUndefined();
    const raw = { hunt_verdict: 'Malicious' } as unknown as NonNullable<ReturnType<typeof graphNode>['raw']>;
    expect(badgesOfNode(graphNode({ raw }), helpers).find((b) => b.key === 'soft-check:hunt')?.label).toBe('Malicious');
  });

  it('keeps one badge per provider, the most severe, and puts the most severe badges first', () => {
    cleanups.push(registerGraphBadgeProvider({
      id: 'two-badges',
      order: 1,
      badgesFor: () => [{ key: 'two-info', tone: 'info', label: 'info' }, { key: 'two-warning', tone: 'warning', label: 'warning' }],
    }));
    cleanups.push(registerGraphBadgeProvider({ id: 'late-error', order: 900, badgesFor: () => [{ key: 'late-error', tone: 'error', label: 'error' }] }));
    const keys = badgesOfNode(graphNode(), helpers).map((b) => b.key);
    expect(keys).not.toContain('two-badges:two-info');
    expect(keys.slice(0, 2)).toEqual(['late-error:late-error', 'two-badges:two-warning']);
  });

  it('draws at most three badges and counts the others', () => {
    const badges = ['a', 'b', 'c', 'd', 'e'].map((key) => ({ key, tone: 'info' as const, label: key }));
    expect(drawnBadges(badges)).toEqual({ drawn: badges.slice(0, MAX_DRAWN_BADGES), more: 2 });
    expect(drawnBadges(badges.slice(0, 2))).toEqual({ drawn: badges.slice(0, 2), more: 0 });
  });
});

describe('built-in badges', () => {
  it('shows the markings as one badge in the colour of the first, never for unmarked elements', () => {
    const marked = graphNode({ markedBy: [
      { id: 'tlp', definition: 'TLP:GREEN', x_opencti_color: '#2e7d32' },
      { id: 'pap', definition: 'PAP:AMBER', x_opencti_color: '#d84315' },
    ] });
    expect(markingBadgeProvider.badgesFor(marked, helpers)).toEqual([
      { key: 'markings', tone: 'neutral', color: '#2e7d32', label: 'TLP:GREEN, PAP:AMBER', legendLabel: 't:Markings', value: 2 },
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
    // created by an inference rule: the inference flag of the object itself
    const created = inferredBadgeProvider.badgesFor(graphNode({ raw: { is_inferred: true } as never }), helpers);
    expect(created).toHaveLength(1);
    expect(created[0].tooltip).toBe('t:Created by an inference rule');
    // only added to the container by an inference rule
    const added = inferredBadgeProvider.badgesFor(graphNode({ isNestedInferred: true, raw: { is_inferred: false } as never }), helpers);
    expect(added).toHaveLength(1);
    expect(added[0].tooltip).toBe('t:Added to this container by an inference rule');
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
