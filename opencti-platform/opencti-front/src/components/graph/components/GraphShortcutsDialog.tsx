import React from 'react';
import { Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Dialog from '../../common/dialog/Dialog';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';

interface GraphShortcutsDialogProps {
  open: boolean;
  onClose: () => void;
  searchable?: boolean;
  exportable?: boolean;
}

/** The keyboard shortcuts of the graphs, as handled by `useGraphKeyboardShortcuts`. */
const GraphShortcutsDialog = ({ open, onClose, searchable = true, exportable = true }: GraphShortcutsDialogProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const shortcuts: { keys: string[]; label: string }[] = [
    { keys: ['F'], label: t_i18n('Fit the whole graph') },
    { keys: ['Shift', 'F'], label: t_i18n('Fit the selection') },
    { keys: ['L'], label: t_i18n('Locate the selection') },
    { keys: ['+'], label: t_i18n('Zoom in') },
    { keys: ['-'], label: t_i18n('Zoom out') },
    { keys: ['Ctrl', 'A'], label: t_i18n('Select all nodes') },
    { keys: ['N'], label: t_i18n('Add neighbours to selection') },
    { keys: ['P'], label: t_i18n('Highlight shortest path between the two selected nodes') },
    { keys: ['H'], label: t_i18n('Hide') },
    { keys: ['Shift', 'H'], label: t_i18n('Show the hidden entities') },
    { keys: ['Esc'], label: t_i18n('Clear selection') },
    { keys: ['Shift', 'F10'], label: t_i18n('Open the context menu') },
    { keys: ['G'], label: t_i18n('Show or minimise the legend') },
    { keys: ['Shift', 'M'], label: t_i18n('Full screen') },
    ...(exportable ? [{ keys: ['Shift', 'E'], label: t_i18n('Export the whole graph as a high-resolution image') }] : []),
    ...(searchable ? [{ keys: ['/'], label: t_i18n('Search in the graph') }] : []),
    { keys: ['?'], label: t_i18n('Keyboard shortcuts') },
  ];
  const key = {
    display: 'inline-block',
    minWidth: 22,
    padding: theme.spacing(0.125, 0.75),
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: theme.borderRadius,
    textAlign: 'center' as const,
  };
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Keyboard shortcuts')} size="small" showCloseButton>
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary, marginBottom: theme.spacing(2) }}>
        {t_i18n('Shortcuts apply while the pointer is over the graph or the focus is inside it.')}
      </Text>
      <Text variant="content-compact" as="dl" style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: theme.spacing(1, 2) }}>
        {shortcuts.map(({ keys, label }) => (
          <React.Fragment key={keys.join('+')}>
            <dt style={{ display: 'flex', gap: theme.spacing(0.5) }}>
              {keys.map((k) => <Text key={k} variant="content-compact-medium" as="kbd" style={key}>{k}</Text>)}
            </dt>
            <dd style={{ margin: 0 }}>{label}</dd>
          </React.Fragment>
        ))}
      </Text>
    </Dialog>
  );
};

export default GraphShortcutsDialog;
