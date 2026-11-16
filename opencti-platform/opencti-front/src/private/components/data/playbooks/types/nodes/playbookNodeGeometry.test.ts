import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CARD, PLAYBOOK_CARD_MENU_BAND, portAnchor } from './playbookNodeGeometry';

// The port pill is 16 px tall, centred on its port: half of it reaches 8 px above the anchor.
const PILL_HALF_HEIGHT = 8;

describe('playbookNodeGeometry portAnchor', () => {
  it('keeps the labelled ports of a horizontal card under the three-dot menu', () => {
    [2, 3].forEach((count) => {
      for (let index = 0; index < count; index += 1) {
        const anchor = portAnchor(index, count, 'horizontal');
        expect(anchor.x).toBe(PLAYBOOK_CARD.width);
        expect(anchor.y - PILL_HALF_HEIGHT).toBeGreaterThanOrEqual(PLAYBOOK_CARD_MENU_BAND);
        expect(anchor.y + PILL_HALF_HEIGHT).toBeLessThanOrEqual(PLAYBOOK_CARD.height);
        expect(Number.isInteger(anchor.y)).toBe(true);
      }
    });
  });

  it('keeps a single horizontal port in the middle of the edge and the vertical ports on the bottom edge', () => {
    expect(portAnchor(0, 1, 'horizontal')).toEqual({ x: PLAYBOOK_CARD.width, y: PLAYBOOK_CARD.height / 2 });
    expect(portAnchor(0, 2, 'vertical')).toEqual({ x: PLAYBOOK_CARD.width / 4, y: PLAYBOOK_CARD.height });
    expect(portAnchor(1, 2, 'vertical')).toEqual({ x: (3 * PLAYBOOK_CARD.width) / 4, y: PLAYBOOK_CARD.height });
  });

  it('orders the horizontal ports top to bottom, out first', () => {
    expect(portAnchor(0, 2, 'horizontal').y).toBeLessThan(portAnchor(1, 2, 'horizontal').y);
  });
});
