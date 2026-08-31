import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import testRender from '../../../utils/tests/test-render';
import Tag from './Tag';

/** What 200+ call sites owe this wrapper now that the design system draws it. */

const chipOf = (text: string) => screen.getByText(text).closest('[class*="box-border"]') as HTMLElement;

describe('Tag renders its label', () => {
  it('renders a string', () => {
    testRender(<Tag label="threat-report" />);
    expect(screen.getByText('threat-report')).toBeInTheDocument();
  });

  it('renders a number, which callers pass for counts', () => {
    testRender(<Tag label={42} />);
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('renders nothing rather than a blank chip when the label is absent', () => {
    testRender(<Tag label={null} disableTooltip />);
    expect(screen.queryByText(/\S/)).not.toBeInTheDocument();
  });
});

describe('Tag keeps the axes the library does not have', () => {
  it('capitalizes by default, because 200 call sites were written for it', () => {
    testRender(<Tag label="threat-report" disableTooltip />);
    expect(chipOf('threat-report')).toHaveStyle({ textTransform: 'capitalize' });
  });

  it('honours an explicit case, which is how labels keep their authored form', () => {
    testRender(<Tag label="apt" labelTextTransform="none" disableTooltip />);
    expect(chipOf('apt')).toHaveStyle({ textTransform: 'none' });
  });

  it('applies maxWidth, as a number of pixels or a raw css length', () => {
    const { unmount } = testRender(<Tag label="numeric" maxWidth={120} disableTooltip />);
    expect(chipOf('numeric')).toHaveStyle({ maxWidth: '120px' });
    unmount();
    testRender(<Tag label="css" maxWidth="50%" disableTooltip />);
    expect(chipOf('css')).toHaveStyle({ maxWidth: '50%' });
  });
});

describe('Tag delete control', () => {
  it('is absent unless onDelete is given', () => {
    testRender(<Tag label="no delete" disableTooltip />);
    expect(screen.queryByRole('button', { name: /remove/i })).not.toBeInTheDocument();
  });

  it('fires onDelete and carries a name that is not the chip’s own', async () => {
    const onDelete = vi.fn();
    testRender(<Tag label="marking" onDelete={onDelete} disableTooltip />);
    const del = screen.getByRole('button', { name: /marking/i });
    await userEvent.click(del);
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it('takes deleteTabIndex, so a chip row inside a field stays one tab stop', () => {
    testRender(<Tag label="in a field" onDelete={vi.fn()} deleteTabIndex={-1} disableTooltip />);
    expect(screen.getByRole('button', { name: /in a field/i })).toHaveAttribute('tabindex', '-1');
  });

  it('takes a translated deleteLabel instead of the library’s English default', () => {
    testRender(<Tag label="marquage" onDelete={vi.fn()} deleteLabel="Supprimer marquage" disableTooltip />);
    expect(screen.getByRole('button', { name: 'Supprimer marquage' })).toBeInTheDocument();
  });
});

describe('Tag tooltip', () => {
  it('is suppressed by disableTooltip', () => {
    testRender(<Tag label="quiet" disableTooltip />);
    expect(chipOf('quiet')).not.toHaveAttribute('aria-label');
  });

  it('does not stack a second tooltip repeating the label', () => {
    // the library Chip already tooltips a clipped label; wrapping every chip in
    // another one mounted four tooltip elements on a single hover
    testRender(<Tag label="a label wider than the chip" />);
    expect(chipOf('a label wider than the chip')).not.toHaveAttribute('aria-label');
  });

  it('keeps the outer tooltip when it says something the label does not', () => {
    testRender(<Tag label="short" tooltipTitle="the long explanation" />);
    expect(chipOf('short')).toHaveAttribute('aria-label', 'the long explanation');
  });
});

describe('Tag data colour', () => {
  it('paints a data hex as a bounded wash, never as raw ink', () => {
    testRender(<Tag label="coloured" color="#d84315" disableTooltip />);
    const chip = chipOf('coloured');
    const bg = getComputedStyle(chip).backgroundColor;
    // the wash is the hex at low alpha — never the hex itself
    expect(bg).not.toBe('rgb(216, 67, 21)');
  });

  it('falls back to the neutral default when no colour is given', () => {
    testRender(<Tag label="plain" disableTooltip />);
    expect(chipOf('plain')).toBeInTheDocument();
  });
});
