import { describe, it, expect } from 'vitest';
import { getHoverHighlight } from './hoverHighlight';
import { buildElements, SAMPLES, transitionId } from './layout/layoutFixtures';

const review = buildElements(SAMPLES.review);
const rfi = buildElements(SAMPLES.rfi);
const submit = transitionId(['NEW'], 'submit', 'IN_REVIEW');
const approve = transitionId(['IN_REVIEW'], 'approve', 'ANALYZED');
const reject = transitionId(['IN_REVIEW'], 'reject', 'NEW');
const reopen = transitionId(['ANALYZED'], 'reopen', 'IN_REVIEW');

describe('getHoverHighlight', () => {
  it('returns null when nothing is hovered', () => {
    expect(getHoverHighlight(null, review.nodes, review.edges)).toBeNull();
  });

  it('returns null for an id that is not on the canvas', () => {
    expect(getHoverHighlight('gone', review.nodes, review.edges)).toBeNull();
  });

  it('lights a status, its parent and child transitions, and the statuses beyond them', () => {
    const highlight = getHoverHighlight('IN_REVIEW', review.nodes, review.edges)!;
    expect([...highlight.nodeIds].sort()).toEqual(['ANALYZED', 'IN_REVIEW', 'NEW', approve, reject, reopen, submit].sort());
    expect([...highlight.edgeIds].sort()).toEqual([
      `e-NEW->${submit}`, `e-${submit}->IN_REVIEW`,
      `e-ANALYZED->${reopen}`, `e-${reopen}->IN_REVIEW`,
      `e-IN_REVIEW->${approve}`, `e-${approve}->ANALYZED`,
      `e-IN_REVIEW->${reject}`, `e-${reject}->NEW`,
    ].sort());
  });

  it('keeps the hovered status placeholder lit, but no other placeholder', () => {
    const highlight = getHoverHighlight('CLOSED', review.nodes, review.edges)!;
    expect(highlight.nodeIds.has('placeholder-CLOSED')).toBe(true);
    expect(highlight.edgeIds.has('e-CLOSED->placeholder-CLOSED')).toBe(true);
  });

  it('lights only the source and target statuses of a hovered transition', () => {
    const highlight = getHoverHighlight(approve, review.nodes, review.edges)!;
    expect([...highlight.nodeIds].sort()).toEqual(['ANALYZED', 'IN_REVIEW', approve].sort());
    expect([...highlight.edgeIds].sort()).toEqual([`e-IN_REVIEW->${approve}`, `e-${approve}->ANALYZED`].sort());
  });

  it('lights every source of a multi-source transition', () => {
    const cancel = transitionId(['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED'], 'cancel', 'CANCELLED');
    const highlight = getHoverHighlight(cancel, rfi.nodes, rfi.edges)!;
    expect([...highlight.nodeIds].sort()).toEqual(['BLOCKED', 'CANCELLED', 'DRAFT', 'IN_PROGRESS', 'PENDING', cancel].sort());
  });

  it('does not light the other sources of a multi-source child transition', () => {
    const cancel = transitionId(['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED'], 'cancel', 'CANCELLED');
    const highlight = getHoverHighlight('DRAFT', rfi.nodes, rfi.edges)!;
    expect(highlight.nodeIds.has(cancel)).toBe(true);
    expect(highlight.nodeIds.has('CANCELLED')).toBe(true);
    expect(highlight.nodeIds.has('BLOCKED')).toBe(false);
    expect(highlight.edgeIds.has(`e-BLOCKED->${cancel}`)).toBe(false);
  });

  it('lights a self-loop once without looping forever', () => {
    const addNote = transitionId(['IN_PROGRESS'], 'add_note', 'IN_PROGRESS');
    const highlight = getHoverHighlight('IN_PROGRESS', rfi.nodes, rfi.edges)!;
    expect(highlight.nodeIds.has(addNote)).toBe(true);
    expect(highlight.edgeIds.has(`e-${addNote}->IN_PROGRESS`)).toBe(true);
  });
});
