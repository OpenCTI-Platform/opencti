import React, { useEffect, useId, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import {
  Badge,
  ButtonGroup,
  ButtonGroupItem,
  Checkbox,
  IconButton,
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
  SearchField,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Text,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import {
  AddOutlined,
  AutorenewOutlined,
  FilterListOutlined,
  FitScreenOutlined,
  GetAppOutlined,
  MoreVertOutlined,
  SettingsOutlined,
  SyncOutlined,
  ViewListOutlined,
  ViewStreamOutlined,
  ViewTimelineOutlined,
  ZoomInOutlined,
  ZoomOutOutlined,
} from '@mui/icons-material';
import Button from '@common/button/Button';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';
import {
  describeTimelineSpan,
  TIMELINE_GROUPING_LABELS,
  TIMELINE_GROUPINGS,
  TIMELINE_KIND_LABELS,
  TIMELINE_KINDS,
  TIMELINE_LANE_LABELS,
  TIMELINE_LANES,
  TIMELINE_SPAN_LABELS,
  TIMELINE_ZOOM_LABELS,
  TIMELINE_ZOOM_WINDOWS,
  type TimelineDomain,
  type TimelineExportFormat,
  type TimelineGrouping,
  type TimelineLane,
  type TimelineSource,
  type TimelineView,
  type TimelineViewState,
  type TimelineZoomWindow,
} from './timelineUtils';

interface ContainerTimelineToolbarProps {
  state: TimelineViewState;
  onChange: (patch: Partial<TimelineViewState>) => void;
  enabledLanes: readonly string[];
  canEdit: boolean;
  liveUpdates: number;
  regenerating: boolean;
  onRefresh: () => void;
  onAdd: () => void;
  onExport: (format: TimelineExportFormat) => void;
  onOpenSettings: () => void;
  onRegenerate: () => void;
  onZoom: (factor: number) => void;
  onFit: () => void;
  // Span of the lanes in view, shown next to the zoom controls
  visibleDomain?: TimelineDomain | null;
}

const WithTooltip = ({ title, children }: { title: string; children: React.ReactElement }) => (
  <Tooltip>
    <TooltipTrigger asChild>{children}</TooltipTrigger>
    <TooltipContent>{title}</TooltipContent>
  </Tooltip>
);

// The design-system switch writes its label in the compact 12px text: the toolbar writes it in the 14px text of its
// selects and buttons, in a box of their height
const ToolbarSwitch = ({ checked, onCheckedChange, label }: { checked: boolean; onCheckedChange: (checked: boolean) => void; label: string }) => {
  const theme = useTheme<Theme>();
  const id = useId();
  return (
    <label
      htmlFor={id}
      style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(1), height: theme.button.sizes.default.height, cursor: 'pointer' }}
    >
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
      <Text variant="content-base">{label}</Text>
    </label>
  );
};

const ContainerTimelineToolbar = ({
  state,
  onChange,
  enabledLanes,
  canEdit,
  liveUpdates,
  regenerating,
  onRefresh,
  onAdd,
  onExport,
  onOpenSettings,
  onRegenerate,
  onZoom,
  onFit,
  visibleDomain,
}: ContainerTimelineToolbarProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const colors = useTimelineColors();
  const visibleSpan = visibleDomain ? describeTimelineSpan(visibleDomain) : null;
  const lanes = TIMELINE_LANES.filter((lane) => enabledLanes.includes(lane));
  // A lane kept in the URL but disabled in the settings since is left out, as it is for the events shown
  const requestedLanes = state.lanes.filter((lane) => lanes.includes(lane));
  const selectedLanes = requestedLanes.length > 0 ? requestedLanes : lanes;
  const allLanesSelected = selectedLanes.length === lanes.length;
  // The search field follows the URL (for example after "Clear filters") and keeps what is typed until it is submitted
  const [searchText, setSearchText] = useState(state.search ?? '');
  useEffect(() => setSearchText(state.search ?? ''), [state.search]);

  const toggleLane = (lane: TimelineLane) => {
    const next = selectedLanes.includes(lane) ? selectedLanes.filter((l) => l !== lane) : [...selectedLanes, lane];
    // Every enabled lane selected is the default view: keep the URL clean
    onChange({ lanes: next.length === lanes.length || next.length === 0 ? [] : next });
  };
  const toggleKind = (kind: string) => {
    const next = state.kinds.includes(kind) ? state.kinds.filter((k) => k !== kind) : [...state.kinds, kind];
    onChange({ kinds: next });
  };
  const sourceValue = state.sources.length === 1 ? state.sources[0] : 'all';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.25), marginBottom: theme.spacing(1.5) }} data-testid="timeline-toolbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
        <ButtonGroup
          size="md"
          value={state.view}
          onValueChange={(value) => value && onChange({ view: value as TimelineView })}
          aria-label={t_i18n('Timeline view')}
        >
          <WithTooltip title={t_i18n('Lanes view')}>
            <ButtonGroupItem value="lanes" aria-label={t_i18n('Lanes view')} icon={<ViewTimelineOutlined fontSize="small" />} />
          </WithTooltip>
          <WithTooltip title={t_i18n('List view')}>
            <ButtonGroupItem value="list" aria-label={t_i18n('List view')} icon={<ViewListOutlined fontSize="small" />} />
          </WithTooltip>
        </ButtonGroup>
        <Select value={state.zoom} onValueChange={(value) => onChange({ zoom: value as TimelineZoomWindow, domain: null })}>
          <SelectTrigger aria-label={t_i18n('Zoom window')} style={{ minWidth: 110 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Zoom window')}>
            {TIMELINE_ZOOM_WINDOWS.map((zoom) => (
              <SelectItem key={zoom} value={zoom}>{t_i18n(TIMELINE_ZOOM_LABELS[zoom])}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {state.view === 'lanes' && (
          <>
            <WithTooltip title={t_i18n('Zoom in')}>
              <IconButton priority="tertiary" size="md" aria-label={t_i18n('Zoom in')} icon={<ZoomInOutlined fontSize="small" />} onClick={() => onZoom(0.6)} />
            </WithTooltip>
            <WithTooltip title={t_i18n('Zoom out')}>
              <IconButton priority="tertiary" size="md" aria-label={t_i18n('Zoom out')} icon={<ZoomOutOutlined fontSize="small" />} onClick={() => onZoom(1 / 0.6)} />
            </WithTooltip>
            <WithTooltip title={t_i18n('Fit the timeline')}>
              <IconButton priority="tertiary" size="md" aria-label={t_i18n('Fit the timeline')} icon={<FitScreenOutlined fontSize="small" />} onClick={onFit} />
            </WithTooltip>
            {visibleSpan && (
              <WithTooltip title={t_i18n('Visible period')}>
                <Text variant="content-base" aria-live="polite" data-testid="timeline-visible-span" style={{ color: colors.textSecondary }}>
                  {t_i18n(TIMELINE_SPAN_LABELS[visibleSpan.unit], { values: { count: visibleSpan.count } })}
                </Text>
              </WithTooltip>
            )}
          </>
        )}
        <Select value={state.grouping} onValueChange={(value) => onChange({ grouping: value as TimelineGrouping })}>
          <SelectTrigger aria-label={t_i18n('Group by')} style={{ minWidth: 110 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Group by')}>
            {TIMELINE_GROUPINGS.map((grouping) => (
              <SelectItem key={grouping} value={grouping}>{t_i18n('By {period}', { values: { period: t_i18n(TIMELINE_GROUPING_LABELS[grouping]).toLowerCase() } })}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div style={{ minWidth: 200, flex: '0 1 260px' }}>
          <SearchField
            value={searchText}
            onChange={(event) => setSearchText(event.target.value)}
            placeholder={t_i18n('Search the timeline')}
            aria-label={t_i18n('Search the timeline')}
            onSubmit={(value) => onChange({ search: value.trim() })}
            onClear={() => {
              setSearchText('');
              onChange({ search: '' });
            }}
          />
        </div>
        <div style={{ flex: 1 }} />
        <Badge content={liveUpdates} max={99} tone="brand" invisible={liveUpdates === 0}>
          <Button
            variant="secondary"
            startIcon={<SyncOutlined fontSize="small" />}
            onClick={onRefresh}
            aria-label={liveUpdates > 0 ? t_i18n('{count, plural, one {# new timeline update} other {# new timeline updates}}, refresh', { values: { count: liveUpdates } }) : t_i18n('Refresh')}
            data-testid="timeline-refresh"
          >
            {liveUpdates > 0 ? t_i18n('New updates') : t_i18n('Refresh')}
          </Button>
        </Badge>
        <Menu>
          <MenuTrigger asChild>
            <IconButton priority="secondary" size="md" aria-label={t_i18n('Export the timeline')} icon={<GetAppOutlined fontSize="small" />} data-testid="timeline-export" />
          </MenuTrigger>
          <MenuContent align="end">
            <MenuLabel>{t_i18n('Export the timeline')}</MenuLabel>
            <MenuItem onSelect={() => onExport('pdf')}>{t_i18n('Export as PDF')}</MenuItem>
            <MenuItem onSelect={() => onExport('csv')}>{t_i18n('Export as CSV')}</MenuItem>
            <MenuItem onSelect={() => onExport('svg')}>{t_i18n('Export as SVG')}</MenuItem>
            <MenuItem onSelect={() => onExport('png')}>{t_i18n('Export as PNG')}</MenuItem>
          </MenuContent>
        </Menu>
        {canEdit && (
          <Menu>
            <MenuTrigger asChild>
              <IconButton priority="secondary" size="md" aria-label={t_i18n('More actions')} icon={<MoreVertOutlined fontSize="small" />} data-testid="timeline-more-actions" />
            </MenuTrigger>
            <MenuContent align="end">
              <MenuItem onSelect={onOpenSettings} data-testid="timeline-open-settings">
                <SettingsOutlined fontSize="small" />
                {t_i18n('Timeline settings')}
              </MenuItem>
              <MenuItem onSelect={onRegenerate} disabled={regenerating}>
                <AutorenewOutlined fontSize="small" />
                {t_i18n('Regenerate the timeline')}
              </MenuItem>
            </MenuContent>
          </Menu>
        )}
        {canEdit && (
          <Button variant="primary" startIcon={<AddOutlined fontSize="small" />} onClick={onAdd} data-testid="timeline-add-milestone">
            {t_i18n('Add an event')}
          </Button>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
        <Menu>
          <MenuTrigger asChild>
            <Button variant="tertiary" startIcon={<ViewStreamOutlined fontSize="small" />} data-testid="timeline-lanes-filter">
              {allLanesSelected ? t_i18n('All lanes') : t_i18n('Lanes ({count})', { values: { count: selectedLanes.length } })}
            </Button>
          </MenuTrigger>
          <MenuContent align="start">
            <MenuLabel>{t_i18n('Lanes')}</MenuLabel>
            {lanes.map((lane) => {
              const active = selectedLanes.includes(lane);
              return (
                <MenuItem
                  key={lane}
                  role="menuitemcheckbox"
                  aria-checked={active}
                  startIcon={<Checkbox checked={active} presentational />}
                  onSelect={(event) => {
                    // Keep the menu open while several lanes are switched
                    event.preventDefault();
                    toggleLane(lane);
                  }}
                  data-testid={`timeline-lane-${lane}`}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(1) }}>
                    {/* The marker of the lane in the lanes view */}
                    <span aria-hidden="true" style={{ width: 4, height: 14, borderRadius: 2, backgroundColor: colors.lanes[lane] }} />
                    {t_i18n(TIMELINE_LANE_LABELS[lane])}
                  </span>
                </MenuItem>
              );
            })}
          </MenuContent>
        </Menu>
        <Menu>
          <MenuTrigger asChild>
            <Button variant="tertiary" startIcon={<FilterListOutlined fontSize="small" />}>
              {state.kinds.length > 0 ? t_i18n('Kinds ({count})', { values: { count: state.kinds.length } }) : t_i18n('All kinds')}
            </Button>
          </MenuTrigger>
          <MenuContent align="start" style={{ maxHeight: 360, overflowY: 'auto' }}>
            <MenuLabel>{t_i18n('Event kinds')}</MenuLabel>
            {TIMELINE_KINDS.map((kind) => {
              const checked = state.kinds.includes(kind);
              // A presentational box renders no label: the row carries the text and the checked state
              return (
                <MenuItem
                  key={kind}
                  role="menuitemcheckbox"
                  aria-checked={checked}
                  startIcon={<Checkbox checked={checked} presentational />}
                  onSelect={(event) => {
                    // Keep the menu open while several kinds are picked
                    event.preventDefault();
                    toggleKind(kind);
                  }}
                >
                  {t_i18n(TIMELINE_KIND_LABELS[kind])}
                </MenuItem>
              );
            })}
            {state.kinds.length > 0 && (
              <>
                <MenuSeparator />
                <MenuItem onSelect={() => onChange({ kinds: [] })}>{t_i18n('Clear the kinds')}</MenuItem>
              </>
            )}
          </MenuContent>
        </Menu>
        <Select value={sourceValue} onValueChange={(value) => onChange({ sources: value === 'all' ? [] : [value as TimelineSource] })}>
          <SelectTrigger aria-label={t_i18n('Event source')} style={{ minWidth: 190 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Event source')}>
            <SelectItem value="all">{t_i18n('All events')}</SelectItem>
            <SelectItem value="derived">{t_i18n('Derived from the knowledge')}</SelectItem>
            <SelectItem value="manual">{t_i18n('Analyst milestones')}</SelectItem>
          </SelectContent>
        </Select>
        <ToolbarSwitch
          checked={state.pinnedOnly}
          onCheckedChange={(checked) => onChange({ pinnedOnly: checked })}
          label={t_i18n('Pinned only')}
        />
        <ToolbarSwitch
          checked={state.includeHidden}
          onCheckedChange={(checked) => onChange({ includeHidden: checked })}
          label={t_i18n('Show hidden events')}
        />
      </div>
    </div>
  );
};

export default ContainerTimelineToolbar;
