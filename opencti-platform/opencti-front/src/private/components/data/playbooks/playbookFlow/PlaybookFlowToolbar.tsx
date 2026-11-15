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

import React, { useEffect, useRef, useState } from 'react';
import { Panel, useReactFlow } from 'reactflow';
import { ButtonGroup, ButtonGroupItem } from '@filigran/design-system';
import { AccountTreeOutlined, CenterFocusStrongOutlined, KeyboardOutlined, RedoOutlined, UndoOutlined, ZoomInOutlined, ZoomOutOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import type { PlaybookLayoutDirection } from '../hooks/usePlaybookLayoutMode';
import PlaybookFlowShortcutsDialog from './PlaybookFlowShortcutsDialog';
import { playbookShortcutFor } from './playbookShortcuts';

// The library item declares a 16x16 glyph. Every control of the row is the md size (36 px), the
// size of the layout switch, so the row has one height.
const GLYPH = { fontSize: 16 };

interface PlaybookFlowToolbarProps {
  direction: PlaybookLayoutDirection;
  onDirectionChange: (direction: PlaybookLayoutDirection) => void;
  // Undo / redo of the session; absent on a read-only canvas.
  history?: { undo: () => void; redo: () => void; canUndo: boolean; canRedo: boolean };
}

// Floating canvas toolbar: the layout direction, then undo and redo, then zoom and fit, then the
// shortcuts cheat sheet. The same actions answer the keyboard (see playbookShortcuts.ts) whenever
// no field has the focus.
const PlaybookFlowToolbar = ({ direction, onDirectionChange, history }: PlaybookFlowToolbarProps) => {
  const { t_i18n } = useFormatter();
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  const [cheatSheetOpen, setCheatSheetOpen] = useState(false);

  // The key handler reads the latest actions through a ref, so it is registered once for the life of
  // the canvas: a re-render (a layout change, a new history state) never leaves a press unanswered.
  const actions = useRef({ zoomIn, zoomOut, fitView, onDirectionChange, history });
  actions.current = { zoomIn, zoomOut, fitView, onDirectionChange, history };

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const action = playbookShortcutFor(event);
      if (!action) return;
      const current = actions.current;
      if (action === 'undo' || action === 'redo') {
        // A read-only canvas, or a dialog or drawer open over it, keeps Ctrl/Cmd+Z to the browser.
        if (!current.history || document.querySelector('[role="dialog"]')) return;
      }
      event.preventDefault();
      if (action === 'undo') {
        if (current.history?.canUndo) current.history.undo();
      } else if (action === 'redo') {
        if (current.history?.canRedo) current.history.redo();
      } else if (action === 'zoomIn') current.zoomIn({ duration: 150 });
      else if (action === 'zoomOut') current.zoomOut({ duration: 150 });
      else if (action === 'fitView') current.fitView({ duration: 200, padding: 0.2 });
      else if (action === 'verticalLayout') current.onDirectionChange('vertical');
      else if (action === 'horizontalLayout') current.onDirectionChange('horizontal');
      else setCheatSheetOpen(true);
    };
    // Capture phase on the window: a control that handles the key itself (a focused toolbar
    // button, the canvas pane) cannot stop the shortcut before it is read.
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, []);

  return (
    <Panel position="top-right">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <ButtonGroup
          size="md"
          value={direction}
          onValueChange={(value: string) => {
            // A click on the item already selected answers an empty value: the layout stays as it is.
            if (value === 'horizontal' || value === 'vertical') onDirectionChange(value);
          }}
          aria-label={t_i18n('Layout')}
        >
          <ButtonGroupItem
            value="vertical"
            aria-label={t_i18n('Vertical layout')}
            icon={<AccountTreeOutlined sx={{ ...GLYPH, transform: 'rotate(90deg)' }} />}
          />
          <ButtonGroupItem
            value="horizontal"
            aria-label={t_i18n('Horizontal layout')}
            icon={<AccountTreeOutlined sx={GLYPH} />}
          />
        </ButtonGroup>
        {history && (
          <>
            <IconButton size="default" aria-label={t_i18n('Undo')} tooltip={t_i18n('Undo')} disabled={!history.canUndo} onClick={history.undo}>
              <UndoOutlined style={GLYPH} />
            </IconButton>
            <IconButton size="default" aria-label={t_i18n('Redo')} tooltip={t_i18n('Redo')} disabled={!history.canRedo} onClick={history.redo}>
              <RedoOutlined style={GLYPH} />
            </IconButton>
          </>
        )}
        <IconButton size="default" aria-label={t_i18n('Zoom out')} tooltip={t_i18n('Zoom out')} onClick={() => zoomOut({ duration: 150 })}>
          <ZoomOutOutlined style={GLYPH} />
        </IconButton>
        <IconButton size="default" aria-label={t_i18n('Zoom in')} tooltip={t_i18n('Zoom in')} onClick={() => zoomIn({ duration: 150 })}>
          <ZoomInOutlined style={GLYPH} />
        </IconButton>
        <IconButton size="default" aria-label={t_i18n('Fit view')} tooltip={t_i18n('Fit view')} onClick={() => fitView({ duration: 200, padding: 0.2 })}>
          <CenterFocusStrongOutlined style={GLYPH} />
        </IconButton>
        <IconButton
          size="default"
          aria-label={t_i18n('Keyboard shortcuts')}
          tooltip={t_i18n('Keyboard shortcuts')}
          onClick={() => setCheatSheetOpen(true)}
        >
          <KeyboardOutlined style={GLYPH} />
        </IconButton>
      </div>
      <PlaybookFlowShortcutsDialog open={cheatSheetOpen} onClose={() => setCheatSheetOpen(false)} />
    </Panel>
  );
};

export default PlaybookFlowToolbar;
