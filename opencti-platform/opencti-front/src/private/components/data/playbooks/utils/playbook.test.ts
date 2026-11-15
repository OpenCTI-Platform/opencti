import { describe, expect, it } from 'vitest';
import { placeholderEdgeIdOf, placeholderIdOf } from './playbook';

describe('Playbook add buttons', () => {
  it('names the "+" of a free out port after its step and its port', () => {
    expect(placeholderIdOf('step-1', 'no-match')).toBe('step-1-no-match-PLACEHOLDER');
    expect(placeholderEdgeIdOf('step-1', 'no-match')).toBe('step-1-no-match-step-1-no-match-PLACEHOLDER');
  });

  it('gives the same "+" the same id every time, so an edit and a reload draw the same button', () => {
    expect(placeholderIdOf('step-1', 'out')).toBe(placeholderIdOf('step-1', 'out'));
    expect(placeholderIdOf('step-1', 'out')).not.toBe(placeholderIdOf('step-1', 'no-match'));
    expect(placeholderIdOf('step-1', 'out')).not.toBe(placeholderIdOf('step-2', 'out'));
  });
});
