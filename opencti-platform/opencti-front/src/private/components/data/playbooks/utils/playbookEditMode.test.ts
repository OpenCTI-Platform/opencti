import { describe, expect, it } from 'vitest';
import { initialPlaybookMode, playbookCanvasAffordances } from '../hooks/usePlaybookEditMode';
import { countDescendantSteps, playbookDeleteOptions } from './playbookDeleteChoices';

describe('Playbook editor mode on open', () => {
  it('opens a stopped playbook in edit mode for a user who can manage playbooks', () => {
    expect(initialPlaybookMode(true, false)).toBe('edit');
  });

  it('opens a running playbook in view mode, even for a user who can manage playbooks', () => {
    expect(initialPlaybookMode(true, true)).toBe('view');
  });

  it('opens every playbook in view mode for a user without Manage Playbooks', () => {
    expect(initialPlaybookMode(false, false)).toBe('view');
    expect(initialPlaybookMode(false, true)).toBe('view');
  });
});

describe('Playbook canvas in view mode', () => {
  it('drops the add buttons, the link insert button, the node menu, the settings and the rewiring', () => {
    expect(playbookCanvasAffordances(false)).toEqual({
      placeholders: false,
      edgeAddButton: false,
      nodeMenu: false,
      nodeOpensSettings: false,
      rewiring: false,
      history: false,
    });
  });

  it('offers every edit control in edit mode', () => {
    expect(Object.values(playbookCanvasAffordances(true)).every(Boolean)).toBe(true);
  });
});

describe('Playbook delete dialog choices', () => {
  //   entry -> a -> b -> c
  //             \-> +  (an add button, not a step)
  const links = [
    { source: 'entry', target: 'a' },
    { source: 'a', target: 'b' },
    { source: 'a', target: 'a-no-match-PLACEHOLDER' },
    { source: 'b', target: 'c' },
  ];
  const isStep = (id: string) => !id.endsWith('PLACEHOLDER');

  it('counts the steps below a step, add buttons left out', () => {
    expect(countDescendantSteps('a', links, isStep)).toBe(2);
    expect(countDescendantSteps('c', links, isStep)).toBe(0);
  });

  it('counts a step reached by two paths once', () => {
    const diamond = [{ source: 'a', target: 'b' }, { source: 'a', target: 'c' }, { source: 'b', target: 'd' }, { source: 'c', target: 'd' }];
    expect(countDescendantSteps('a', diamond, isStep)).toBe(3);
  });

  it('offers this step only (default) or the whole branch for a step with children', () => {
    expect(playbookDeleteOptions(2, false)).toEqual({ choices: ['step', 'branch'], defaultChoice: 'step', descendants: 2 });
  });

  it('keeps a simple confirmation for a leaf', () => {
    expect(playbookDeleteOptions(0, false)).toEqual({ choices: ['step'], defaultChoice: 'step', descendants: 0 });
  });

  it('offers only the whole branch for the entry point with children', () => {
    expect(playbookDeleteOptions(3, true)).toEqual({ choices: ['branch'], defaultChoice: 'branch', descendants: 3 });
  });
});
