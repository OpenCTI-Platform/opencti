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

import React from 'react';
import { useTheme } from '@mui/material/styles';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { PLAYBOOK_SHORTCUTS } from './playbookShortcuts';

interface PlaybookFlowShortcutsDialogProps {
  open: boolean;
  onClose: () => void;
}

// The in-app cheat sheet of the canvas: the keyboard shortcuts, then the mouse gestures.
const PlaybookFlowShortcutsDialog = ({ open, onClose }: PlaybookFlowShortcutsDialogProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const keyStyle: React.CSSProperties = {
    display: 'inline-block',
    minWidth: 20,
    padding: '0 6px',
    borderRadius: 4,
    border: `1px solid ${theme.palette.divider}`,
    backgroundColor: theme.palette.background.default,
    fontFamily: 'monospace',
    fontSize: 12,
    lineHeight: '20px',
    textAlign: 'center',
  };
  const gestures = [
    { gesture: t_i18n('Right click on a step'), label: t_i18n('Open the step menu') },
    { gesture: t_i18n('Drag the end of a link'), label: t_i18n('Reconnect the link') },
    { gesture: t_i18n('Drag from an output to a step'), label: t_i18n('Move the step and its branch') },
  ];
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Keyboard shortcuts')} size="small" showCloseButton>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <tbody>
          {PLAYBOOK_SHORTCUTS.map((shortcut) => (
            <tr key={shortcut.action}>
              <td style={{ padding: '6px 0' }}>{t_i18n(shortcut.label)}</td>
              <td style={{ padding: '6px 0', textAlign: 'right' }}>
                {shortcut.keys.map((key) => <kbd key={key} style={keyStyle}>{key}</kbd>)}
              </td>
            </tr>
          ))}
          {gestures.map(({ gesture, label }) => (
            <tr key={gesture}>
              <td style={{ padding: '6px 0' }}>{label}</td>
              <td style={{ padding: '6px 0', textAlign: 'right', color: theme.palette.text?.secondary }}>{gesture}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Dialog>
  );
};

export default PlaybookFlowShortcutsDialog;
