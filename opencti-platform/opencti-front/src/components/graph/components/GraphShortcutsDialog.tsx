import React from 'react';
import { useTheme } from '@mui/material/styles';
import Dialog from '../../common/dialog/Dialog';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';

interface GraphShortcutsDialogProps {
  open: boolean;
  onClose: () => void;
}

/** The keyboard shortcuts of the graphs, as handled by `useGraphKeyboardShortcuts`. */
const GraphShortcutsDialog = ({ open, onClose }: GraphShortcutsDialogProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const shortcuts: { keys: string[]; label: string }[] = [
    { keys: ['F'], label: t_i18n('Fit the whole graph') },
    { keys: ['Shift', 'F'], label: t_i18n('Fit the selection') },
    { keys: ['L'], label: t_i18n('Locate the selection') },
    { keys: ['+'], label: t_i18n('Zoom in') },
    { keys: ['-'], label: t_i18n('Zoom out') },
    { keys: ['Ctrl', 'A'], label: t_i18n('Select all nodes') },
    { keys: ['N'], label: t_i18n('Select with its neighbours') },
    { keys: ['P'], label: t_i18n('Highlight the shortest path between the two selected nodes') },
    { keys: ['H'], label: t_i18n('Hide from the view') },
    { keys: ['Shift', 'H'], label: t_i18n('Show the hidden entities') },
    { keys: ['Esc'], label: t_i18n('Clear the selection') },
    { keys: ['G'], label: t_i18n('Show the legend') },
    { keys: ['Shift', 'M'], label: t_i18n('Show the graph full screen') },
    { keys: ['Shift', 'E'], label: t_i18n('Export the whole graph as a high-resolution image') },
    { keys: ['/'], label: t_i18n('Search in the graph') },
    { keys: ['?'], label: t_i18n('Keyboard shortcuts') },
  ];
  const key = {
    display: 'inline-block',
    minWidth: 22,
    padding: theme.spacing(0, 0.75),
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: 4,
    fontSize: 12,
    lineHeight: '20px',
    textAlign: 'center' as const,
    fontFamily: 'inherit',
  };
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Keyboard shortcuts')} size="small" showCloseButton>
      <p style={{ marginTop: 0, color: theme.palette.text.secondary, fontSize: 13 }}>
        {t_i18n('Shortcuts apply while the pointer is over the graph or the focus is inside it.')}
      </p>
      <dl style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: theme.spacing(1, 2), margin: 0 }}>
        {shortcuts.map(({ keys, label }) => (
          <React.Fragment key={keys.join('+')}>
            <dt style={{ display: 'flex', gap: 4 }}>
              {keys.map((k) => <kbd key={k} style={key}>{k}</kbd>)}
            </dt>
            <dd style={{ margin: 0, fontSize: 13 }}>{label}</dd>
          </React.Fragment>
        ))}
      </dl>
    </Dialog>
  );
};

export default GraphShortcutsDialog;
