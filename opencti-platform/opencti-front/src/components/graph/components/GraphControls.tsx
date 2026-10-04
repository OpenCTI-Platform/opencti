import React, { ReactNode } from 'react';
import { IconButton, Paper, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import {
  CenterFocusWeakOutlined,
  FilterCenterFocusOutlined,
  FullscreenExitOutlined,
  FullscreenOutlined,
  ImageOutlined,
  KeyboardOutlined,
  LegendToggleOutlined,
  MyLocationOutlined,
  ZoomInOutlined,
  ZoomOutOutlined,
} from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';

interface ControlProps {
  label: string;
  shortcut?: string;
  icon: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  active?: boolean;
}

const Control = ({ label, shortcut, icon, onClick, disabled, active }: ControlProps) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <IconButton
        priority="tertiary"
        size="sm"
        aria-label={label}
        aria-keyshortcuts={shortcut}
        aria-pressed={active}
        active={active}
        disabled={disabled}
        icon={icon}
        onClick={onClick}
      />
    </TooltipTrigger>
    <TooltipContent side="right">
      {shortcut ? `${label} (${shortcut})` : label}
    </TooltipContent>
  </Tooltip>
);

export interface GraphControlsProps {
  hasSelection: boolean;
  is3D: boolean;
  isFullscreen: boolean;
  showLegend: boolean;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFit: () => void;
  onFitSelection: () => void;
  onLocate: () => void;
  onToggleLegend: () => void;
  onToggleFullscreen: () => void;
  onExport: () => void;
  onShowShortcuts: () => void;
}

/**
 * The navigation controls floating over the canvas: zoom, framing, legend, full screen, export
 * and the keyboard shortcuts, each also reachable from the keyboard. The graph places them in its
 * top left corner, next to the counter row.
 */
const GraphControls = ({
  hasSelection,
  is3D,
  isFullscreen,
  showLegend,
  onZoomIn,
  onZoomOut,
  onFit,
  onFitSelection,
  onLocate,
  onToggleLegend,
  onToggleFullscreen,
  onExport,
  onShowShortcuts,
}: GraphControlsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <Paper
      elevation={2}
      padding={0}
      className={EXPORT_REMOVE_CLASS}
      role="toolbar"
      aria-orientation="vertical"
      aria-label={t_i18n('Graph view controls')}
      data-graph-panel=""
      style={{ pointerEvents: 'auto' }}
      onMouseDown={(event) => event.stopPropagation()}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: theme.spacing(0.5) }}>
        {!is3D && (
          <>
            <Control label={t_i18n('Zoom in')} shortcut="+" icon={<ZoomInOutlined fontSize="small" />} onClick={onZoomIn} />
            <Control label={t_i18n('Zoom out')} shortcut="-" icon={<ZoomOutOutlined fontSize="small" />} onClick={onZoomOut} />
          </>
        )}
        <Control label={t_i18n('Fit the whole graph')} shortcut="F" icon={<CenterFocusWeakOutlined fontSize="small" />} onClick={onFit} />
        <Control
          label={t_i18n('Fit the selection')}
          shortcut="Shift+F"
          icon={<FilterCenterFocusOutlined fontSize="small" />}
          onClick={onFitSelection}
          disabled={!hasSelection}
        />
        {!is3D && (
          <Control
            label={t_i18n('Locate the selection')}
            shortcut="L"
            icon={<MyLocationOutlined fontSize="small" />}
            onClick={onLocate}
            disabled={!hasSelection}
          />
        )}
        <span aria-hidden style={{ margin: theme.spacing(0.25, 0.5), borderTop: `1px solid ${theme.palette.divider}` }} />
        {!is3D && (
          <Control
            label={showLegend ? t_i18n('Hide the legend') : t_i18n('Show the legend')}
            shortcut="G"
            icon={<LegendToggleOutlined fontSize="small" />}
            onClick={onToggleLegend}
            active={showLegend}
          />
        )}
        <Control
          label={isFullscreen ? t_i18n('Leave full screen') : t_i18n('Show the graph full screen')}
          shortcut="Shift+M"
          icon={isFullscreen ? <FullscreenExitOutlined fontSize="small" /> : <FullscreenOutlined fontSize="small" />}
          onClick={onToggleFullscreen}
          active={isFullscreen}
        />
        {!is3D && (
          <Control
            label={t_i18n('Export the whole graph as a high-resolution image')}
            shortcut="Shift+E"
            icon={<ImageOutlined fontSize="small" />}
            onClick={onExport}
          />
        )}
        <Control label={t_i18n('Keyboard shortcuts')} shortcut="?" icon={<KeyboardOutlined fontSize="small" />} onClick={onShowShortcuts} />
      </div>
    </Paper>
  );
};

export default GraphControls;
