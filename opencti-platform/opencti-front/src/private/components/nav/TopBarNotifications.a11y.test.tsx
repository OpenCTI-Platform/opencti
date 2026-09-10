import { computeAccessibleDescription, computeAccessibleName } from 'dom-accessibility-api';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { NotificationsOutlined } from '@mui/icons-material';
import React from 'react';
import { describe, expect, it } from 'vitest';
import TopBarIconLink from './TopBarIconLink';
import testRender from '../../../utils/tests/test-render';

const renderAsTheBarDoes = (unread: number) => testRender(
  <Tooltip>
    <TooltipTrigger asChild>
      <TopBarIconLink
        aria-label="Notifications"
        to="/dashboard/profile/notifications/alerts"
        icon={<NotificationsOutlined fontSize="medium" />}
        badge={{
          content: unread,
          dot: true,
          invisible: unread === 0,
          accessibleText: `${unread} unread`,
        }}
      />
    </TooltipTrigger>
    <TooltipContent>Notifications</TooltipContent>
  </Tooltip>,
);

const controlIn = (root: HTMLElement) => root.querySelector('a') as HTMLElement;

describe('the notifications control, composed as the bar composes it', () => {
  it('keeps its own accessible name', () => {
    const { baseElement } = renderAsTheBarDoes(4);
    expect(computeAccessibleName(controlIn(baseElement))).toBe('Notifications');
  });

  it('announces the count as the control accessible description', () => {
    const { baseElement } = renderAsTheBarDoes(4);
    const description = computeAccessibleDescription(controlIn(baseElement));
    expect(description).toContain('4');
    expect(description).toContain('unread');
  });

  it('resolves that description outside every aria-hidden subtree', () => {
    const { baseElement } = renderAsTheBarDoes(4);
    const described = controlIn(baseElement).getAttribute('aria-describedby');
    expect(described).toBeTruthy();
    const target = baseElement.querySelector(`#${described}`);
    expect(target).not.toBeNull();
    // The exact regression: the description existed, and computed to nothing,
    // because it pointed inside the hidden glyph.
    expect(target?.closest('[aria-hidden="true"]')).toBeNull();
  });

  it('says nothing extra when there is nothing unread', () => {
    const { baseElement } = renderAsTheBarDoes(0);
    expect(computeAccessibleName(controlIn(baseElement))).toBe('Notifications');
    expect(computeAccessibleDescription(controlIn(baseElement))).toBe('');
  });

  it('still lets the tooltip trigger reach the control it wraps', () => {
    const { baseElement } = renderAsTheBarDoes(4);
    // `data-state` only lands here if what TooltipTrigger cloned survived the journey to the
    // anchor.
    expect(controlIn(baseElement).getAttribute('data-state')).toBe('closed');
  });
});
