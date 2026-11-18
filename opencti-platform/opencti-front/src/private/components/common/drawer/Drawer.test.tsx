import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import Drawer from './Drawer';
import testRender from '../../../../utils/tests/test-render';

describe('Drawer', () => {
  it('gives nested drawers distinct accessible title ids', () => {
    testRender(
      <Drawer title="Outer drawer" open onClose={() => {}}>
        <Drawer title="Inner drawer" open onClose={() => {}}>
          <div />
        </Drawer>
      </Drawer>,
    );

    const outer = screen.getByRole('dialog', { name: 'Outer drawer', hidden: true });
    const inner = screen.getByRole('dialog', { name: 'Inner drawer', hidden: true });
    expect(outer.getAttribute('aria-labelledby')).not.toBe(inner.getAttribute('aria-labelledby'));
  });
});
