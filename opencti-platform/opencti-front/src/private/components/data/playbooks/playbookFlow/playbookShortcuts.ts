/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

export type PlaybookShortcutAction = 'zoomIn' | 'zoomOut' | 'fitView' | 'verticalLayout' | 'horizontalLayout' | 'undo' | 'redo' | 'cheatSheet';

export interface PlaybookShortcut {
  action: PlaybookShortcutAction;
  keys: string[];
  label: string;
}

// The platform modifier in a key list: shown as the key of the user's platform (see shortcutKeyLabel).
export const MOD_KEY = 'Mod';

// The canvas shortcuts, in the order the cheat sheet lists them. Labels are catalog keys.
export const PLAYBOOK_SHORTCUTS: PlaybookShortcut[] = [
  { action: 'zoomIn', keys: ['+'], label: 'Zoom in' },
  { action: 'zoomOut', keys: ['-'], label: 'Zoom out' },
  { action: 'fitView', keys: ['F'], label: 'Fit view' },
  { action: 'verticalLayout', keys: ['V'], label: 'Vertical layout' },
  { action: 'horizontalLayout', keys: ['H'], label: 'Horizontal layout' },
  { action: 'undo', keys: [MOD_KEY, 'Z'], label: 'Undo' },
  { action: 'redo', keys: ['Shift', MOD_KEY, 'Z'], label: 'Redo' },
  { action: 'cheatSheet', keys: ['?'], label: 'Keyboard shortcuts' },
];

interface PlatformLike {
  platform?: string;
  userAgentData?: { platform?: string };
}

// True on macOS and iOS, where the shortcuts use Command instead of Control.
export const isApplePlatform = (nav: PlatformLike | undefined = typeof navigator !== 'undefined' ? navigator as PlatformLike : undefined) => {
  const platform = nav?.userAgentData?.platform || nav?.platform || '';
  return /mac|iphone|ipad|ipod/i.test(platform);
};

// The label of one key of a shortcut: the platform modifier is the Command sign on macOS, Ctrl elsewhere.
export const shortcutKeyLabel = (key: string, apple: boolean = isApplePlatform()) => {
  if (key !== MOD_KEY) return key;
  return apple ? '\u2318' : 'Ctrl';
};

// Undo and redo answer anywhere on the page (except in a field or over a dialog); every other shortcut
// answers only while the focus is on the canvas.
export const isGlobalShortcut = (action: PlaybookShortcutAction) => action === 'undo' || action === 'redo';

interface ShortcutKeyEvent {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  target?: EventTarget | null;
}

interface TargetLike {
  tagName?: string;
  isContentEditable?: boolean;
  getAttribute?: (name: string) => string | null;
  closest?: (selectors: string) => unknown;
}

// Roles of the controls that read single keys themselves (typeahead of a select, a list, a menu).
const FIELD_ROLES = new Set(['textbox', 'searchbox', 'combobox', 'listbox', 'option', 'spinbutton', 'slider', 'menu', 'menuitem']);
const OVERLAY_SELECTOR = '[role="dialog"], [role="alertdialog"], [aria-modal="true"], .MuiDrawer-root, [role="combobox"], [role="listbox"], [role="menu"]';

// A field, a control with its own typeahead, or anything inside a dialog or drawer keeps its keys.
export const isFieldOrOverlayTarget = (target: EventTarget | null | undefined) => {
  const element = target as TargetLike | null | undefined;
  if (!element) return false;
  if (element.isContentEditable) return true;
  const tag = (element.tagName ?? '').toUpperCase();
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  const role = typeof element.getAttribute === 'function' ? element.getAttribute('role') : null;
  if (role && FIELD_ROLES.has(role)) return true;
  return typeof element.closest === 'function' && Boolean(element.closest(OVERLAY_SELECTOR));
};

// The shortcut a key press asks for, or null: never in a field, a select, a list or a menu, never inside
// a dialog or drawer (the control keeps its own keys and undo), never with a modifier except Mod+Z and
// Shift+Mod+Z (Ctrl+Y too) for undo and redo.
export const playbookShortcutFor = (event: ShortcutKeyEvent): PlaybookShortcutAction | null => {
  if (isFieldOrOverlayTarget(event.target)) return null;
  if ((event.ctrlKey || event.metaKey) && !event.altKey) {
    const key = event.key.toLowerCase();
    if (key === 'z') return event.shiftKey ? 'redo' : 'undo';
    if (key === 'y' && event.ctrlKey && !event.shiftKey) return 'redo';
    return null;
  }
  if (event.ctrlKey || event.metaKey || event.altKey) return null;
  switch (event.key) {
    case '+':
    case '=':
      return 'zoomIn';
    case '-':
      return 'zoomOut';
    case 'f':
    case 'F':
      return 'fitView';
    case 'v':
    case 'V':
      return 'verticalLayout';
    case 'h':
    case 'H':
      return 'horizontalLayout';
    case '?':
      return 'cheatSheet';
    default:
      return null;
  }
};
