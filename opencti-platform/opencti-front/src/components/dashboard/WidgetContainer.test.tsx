import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import WidgetContainer from './WidgetContainer';

describe('WidgetContainer', () => {
  it('names its warning for the screen readers, and shows it to the keyboard', async () => {
    const warning = 'Only the 10 highest values are displayed.';
    const { getByRole, findByRole } = testRender(
      <WidgetContainer title="Reports by label" warning={warning}>
        <div>chart</div>
      </WidgetContainer>,
    );
    const trigger = getByRole('button', { name: warning });
    expect(trigger.tabIndex).toEqual(0);
    act(() => {
      fireEvent.focus(trigger);
    });
    expect((await findByRole('tooltip')).textContent).toContain(warning);
  });

  it('has no warning trigger without warning', () => {
    const { queryByRole } = testRender(
      <WidgetContainer title="Reports by label">
        <div>chart</div>
      </WidgetContainer>,
    );
    expect(queryByRole('button')).toBeNull();
  });
});
