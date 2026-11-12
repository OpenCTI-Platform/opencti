import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import moment from 'moment';
import testRender, { createMockUserContext } from '../utils/tests/test-render';
import { DateDisplay, DEFAULT_DATE_DISPLAY } from '../utils/dateDisplay';
import { EMPTY_VALUE } from '../utils/String';
import ItemDueDate from './ItemDueDate';

// Built in local time, as dates are displayed in the time zone of the browser.
const dueDate = new Date(2026, 10, 5, 18, 0, 0).toISOString();
const offset = moment(dueDate).format('Z');

const renderDueDate = (variant: string, dateDisplay: DateDisplay = DEFAULT_DATE_DISPLAY, date: string | null = dueDate) => testRender(
  <ItemDueDate due_date={date} variant={variant} />,
  { userContext: { ...createMockUserContext(), dateDisplay } },
);

describe('ItemDueDate', () => {
  it('keeps the long date without time in lists by default', () => {
    renderDueDate('inList');
    expect(screen.getByText('November 5, 2026')).toBeInTheDocument();
  });

  it('follows the date display of tables in lists', () => {
    renderDueDate('inList', { dateFormat: 'iso', timeFormat: 'seconds' });
    expect(screen.getByText(`2026-11-05 18:00:00${offset}`)).toBeInTheDocument();
  });

  it('keeps the long date and time in an element, whatever the date display of tables', () => {
    renderDueDate('inElement', { dateFormat: 'iso', timeFormat: 'seconds' });
    expect(screen.getByText(/^November 5, 2026/)).toBeInTheDocument();
  });

  it('displays an empty value without due date', () => {
    renderDueDate('inList', DEFAULT_DATE_DISPLAY, null);
    expect(screen.getByText(EMPTY_VALUE)).toBeInTheDocument();
  });
});
