import { KeyboardEvent, MouseEvent, UIEvent } from 'react';
import { APP_BASE_PATH } from '../relay/environment';

const stopEvent = (event: UIEvent) => {
  event.stopPropagation();
  event.preventDefault();
};

// event.button 1 handles middleButton mouse click
export const shouldOpenInNewTabMouseEvent = (event: MouseEvent) => event.ctrlKey || event.metaKey || event.button === 1;

// window.open() does not know the router basename: an in-app path only
// resolves on a platform served under a sub-path once prefixed with it.
export const openInNewTab = (path: string) => window.open(`${APP_BASE_PATH}${path}`, '_blank');

// Handlers for an element that navigates but cannot be a real anchor (a chip,
// possibly nested in a card rendered as a link): ctrl/cmd click opens a new
// tab like a link would, and so does a middle click, which only fires auxclick.
export const navigationClickHandlers = (path: string, navigate: (path: string) => void) => ({
  onClick: (event: MouseEvent) => {
    stopEvent(event);
    if (shouldOpenInNewTabMouseEvent(event)) {
      openInNewTab(path);
    } else {
      navigate(path);
    }
  },
  onAuxClick: (event: MouseEvent) => {
    if (event.button !== 1) return;
    stopEvent(event);
    openInNewTab(path);
  },
});

// For the actions nested in a card or row rendered as a link, as both onClick
// and onAuxClick (a middle click only fires auxclick, and would open the link
// in a new tab): their clicks must neither bubble to the link nor follow it.
// Only a click inside the link in the DOM has its default cancelled: React also
// bubbles here the clicks of the portals (menus, dialogs, drawers) an action
// mounts, and those, like any click outside a link, keep theirs (checkbox
// toggle, form submit, file picker).
export const stopLinkNavigation = (event: MouseEvent<HTMLElement>) => {
  if (event.type === 'auxclick' && event.button !== 1) return;
  event.stopPropagation();
  const { currentTarget } = event;
  if (currentTarget.contains(event.target as Node) && currentTarget.closest('a[href]')) {
    event.preventDefault();
  }
};

// Keyboard activation for an element given role="button": Enter and Space run
// the action, as they would on a native <button> (Space without scrolling the
// page). Usage: onKeyDown={onActivationKey(() => sortBy(field))}
export const onActivationKey = (action: (event: KeyboardEvent) => void) => (event: KeyboardEvent) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    action(event);
  }
};

export default stopEvent;
