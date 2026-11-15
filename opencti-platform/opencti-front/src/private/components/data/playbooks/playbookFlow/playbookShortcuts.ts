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

export type PlaybookShortcutAction = 'zoomIn' | 'zoomOut' | 'fitView' | 'verticalLayout' | 'horizontalLayout' | 'cheatSheet';

export interface PlaybookShortcut {
  action: PlaybookShortcutAction;
  keys: string[];
  label: string;
}

// The canvas shortcuts, in the order the cheat sheet lists them. Labels are catalog keys.
export const PLAYBOOK_SHORTCUTS: PlaybookShortcut[] = [
  { action: 'zoomIn', keys: ['+'], label: 'Zoom in' },
  { action: 'zoomOut', keys: ['-'], label: 'Zoom out' },
  { action: 'fitView', keys: ['F'], label: 'Fit view' },
  { action: 'verticalLayout', keys: ['V'], label: 'Vertical layout' },
  { action: 'horizontalLayout', keys: ['H'], label: 'Horizontal layout' },
  { action: 'cheatSheet', keys: ['?'], label: 'Keyboard shortcuts' },
];

interface ShortcutKeyEvent {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  altKey?: boolean;
  target?: EventTarget | null;
}

const isTypingTarget = (target: EventTarget | null | undefined) => {
  const element = target as { tagName?: string; isContentEditable?: boolean } | null | undefined;
  if (!element) return false;
  if (element.isContentEditable) return true;
  const tag = (element.tagName ?? '').toUpperCase();
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
};

// The shortcut a key press asks for, or null: never while typing in a field, never with a modifier
// (the browser and the operating system keep theirs).
export const playbookShortcutFor = (event: ShortcutKeyEvent): PlaybookShortcutAction | null => {
  if (event.ctrlKey || event.metaKey || event.altKey) return null;
  if (isTypingTarget(event.target)) return null;
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
