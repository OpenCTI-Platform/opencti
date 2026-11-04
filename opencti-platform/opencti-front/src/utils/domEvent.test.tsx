/* The `<div onClick>` wrappers below are test fixtures standing in for clickable
   rows/cards, to assert that clicks do or do not bubble up to them. */
/* eslint-disable jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions */
import React from 'react';
import { createPortal } from 'react-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { Link, MemoryRouter, useLocation } from 'react-router';
import { navigationClickHandlers, onActivationKey, openInNewTab, stopLinkNavigation } from './domEvent';

vi.mock('../relay/environment', () => ({ APP_BASE_PATH: '/opencti' }));

const CurrentPath = () => <span data-testid="path">{useLocation().pathname}</span>;

const renderInRouter = (ui: React.ReactNode) => render(
  <MemoryRouter initialEntries={['/start']}>
    {ui}
    <CurrentPath />
  </MemoryRouter>,
);

const auxClick = (element: Element, button: number) => fireEvent(
  element,
  new MouseEvent('auxclick', { bubbles: true, cancelable: true, button }),
);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('openInNewTab', () => {
  it('prefixes the platform base path, which window.open does not know', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    openInNewTab('/dashboard/settings');
    expect(open).toHaveBeenCalledWith('/opencti/dashboard/settings', '_blank');
  });
});

describe('navigationClickHandlers', () => {
  const renderChip = () => {
    const navigate = vi.fn();
    const parentClick = vi.fn();
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    render(
      <div onClick={parentClick}>
        <button type="button" {...navigationClickHandlers('/target', navigate)}>chip</button>
      </div>,
    );
    return { chip: screen.getByRole('button', { name: 'chip' }), navigate, parentClick, open };
  };

  it('navigates in place on a plain click, without reaching the parent', () => {
    const { chip, navigate, parentClick, open } = renderChip();
    expect(fireEvent.click(chip)).toBe(false);
    expect(navigate).toHaveBeenCalledWith('/target');
    expect(open).not.toHaveBeenCalled();
    expect(parentClick).not.toHaveBeenCalled();
  });

  it.each([['ctrl', { ctrlKey: true }], ['cmd', { metaKey: true }]])('opens a new tab under the base path on %s click', (_, modifier) => {
    const { chip, navigate, open } = renderChip();
    fireEvent.click(chip, modifier);
    expect(open).toHaveBeenCalledWith('/opencti/target', '_blank');
    expect(navigate).not.toHaveBeenCalled();
  });

  it('opens a new tab on middle click, which only fires auxclick', () => {
    const { chip, navigate, parentClick, open } = renderChip();
    expect(auxClick(chip, 1)).toBe(false);
    expect(open).toHaveBeenCalledWith('/opencti/target', '_blank');
    expect(navigate).not.toHaveBeenCalled();
    expect(parentClick).not.toHaveBeenCalled();
  });

  it('leaves the right button alone', () => {
    const { chip, navigate, open } = renderChip();
    expect(auxClick(chip, 2)).toBe(true);
    expect(open).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });
});

describe('stopLinkNavigation', () => {
  const PortalCheckbox = () => createPortal(<input type="checkbox" aria-label="accept" />, document.body);

  it('runs a nested action without following the enclosing link', () => {
    const action = vi.fn();
    renderInRouter(
      <Link to="/card">
        card
        <div onClick={stopLinkNavigation}>
          <button type="button" onClick={action}>deploy</button>
        </div>
      </Link>,
    );
    expect(fireEvent.click(screen.getByRole('button', { name: 'deploy' }))).toBe(false);
    expect(action).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('path')).toHaveTextContent('/start');

    fireEvent.click(screen.getByText('card'));
    expect(screen.getByTestId('path')).toHaveTextContent('/card');
  });

  const renderNestedAction = () => {
    const outsideAuxClick = vi.fn();
    renderInRouter(
      <div onAuxClick={outsideAuxClick}>
        <Link to="/card">
          <div onClick={stopLinkNavigation} onAuxClick={stopLinkNavigation}>
            <button type="button">deploy</button>
          </div>
        </Link>
      </div>,
    );
    return { action: screen.getByRole('button', { name: 'deploy' }), outsideAuxClick };
  };

  it('keeps a middle click on a nested action from opening the enclosing link in a new tab', () => {
    const { action, outsideAuxClick } = renderNestedAction();
    expect(auxClick(action, 1)).toBe(false);
    expect(outsideAuxClick).not.toHaveBeenCalled();
  });

  it('leaves the right button alone on a nested action', () => {
    const { action, outsideAuxClick } = renderNestedAction();
    expect(auxClick(action, 2)).toBe(true);
    expect(outsideAuxClick).toHaveBeenCalledTimes(1);
  });

  it('keeps the default of a portal the action mounts, and still never follows the link', () => {
    renderInRouter(
      <Link to="/card">
        <div onClick={stopLinkNavigation}>
          <PortalCheckbox />
        </div>
      </Link>,
    );
    const checkbox = screen.getByRole('checkbox', { name: 'accept' });
    expect(fireEvent.click(checkbox)).toBe(true);
    expect(checkbox).toBeChecked();
    expect(screen.getByTestId('path')).toHaveTextContent('/start');
  });

  it('only stops the propagation outside a link, so a nested file picker or checkbox keeps working', () => {
    const parentClick = vi.fn();
    render(
      <div onClick={parentClick}>
        <div onClick={stopLinkNavigation}>
          <input type="checkbox" aria-label="pick" />
        </div>
      </div>,
    );
    const checkbox = screen.getByRole('checkbox', { name: 'pick' });
    expect(fireEvent.click(checkbox)).toBe(true);
    expect(checkbox).toBeChecked();
    expect(parentClick).not.toHaveBeenCalled();
  });
});

describe('onActivationKey', () => {
  const renderButton = () => {
    const action = vi.fn();
    render(<span role="button" tabIndex={0} onKeyDown={onActivationKey(action)}>sort</span>);
    return { button: screen.getByRole('button', { name: 'sort' }), action };
  };

  it.each(['Enter', ' '])('runs the action on %j, without the key\'s default behaviour', (key) => {
    const { button, action } = renderButton();
    const notCancelled = fireEvent.keyDown(button, { key });
    expect(action).toHaveBeenCalledTimes(1);
    expect(notCancelled).toBe(false);
  });

  it('ignores the other keys', () => {
    const { button, action } = renderButton();
    const notCancelled = fireEvent.keyDown(button, { key: 'a' });
    expect(action).not.toHaveBeenCalled();
    expect(notCancelled).toBe(true);
  });
});
