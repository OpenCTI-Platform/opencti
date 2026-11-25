import React, { ReactNode } from 'react';
import { ImageOutlined, LocalFireDepartmentOutlined, SecurityOutlined } from '@mui/icons-material';
import { Icon, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import EntitySelect, { EntityOption } from '@components/common/form/EntitySelect';
import { formatNameList } from '@components/techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixCellDecoration';
import ToolbarShell, { type ToolbarAction, type ToolbarSlot } from '../../../../../components/graph/ToolbarShell';
import { GroupDivider } from '../../../../../components/graph/components/ToolbarParts';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { GRAPH_TOOLBAR_HEIGHT, GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE } from '../../../../../components/graph/utils/graphFraming';
import { TOOLBAR_GAP_PX } from '../../../../../components/graph/utils/graphToolbarOverflow';
import { useFormatter } from '../../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNFRONTENDEXPORT } from '../../../../../utils/hooks/useGranted';
import { INVESTIGATION_MATRIX_EXPORT_ID } from '../InvestigationViewSwitcher';
import HeatmapLegend from './HeatmapLegend';
import { useMatrixImageExport } from './useMatrixImageExport';
import { formatAttackPatternLabel, type InvestigationAttackPattern } from './investigationMatrixUtils';
import type { InvestigationMatrixSettings, InvestigationMatrixSettingsChange } from './investigationMatrixSettings';

/** Groups of the matrix toolbar, in their order from left to right. */
export const MATRIX_TOOLBAR_GROUPS = ['filters', 'posture', 'export'] as const;
export type MatrixToolbarGroup = typeof MATRIX_TOOLBAR_GROUPS[number];

export interface InvestigationMatrixToolbarProps {
  outsideKillChain: InvestigationAttackPattern[];
  killChains: string[];
  killChain: string | undefined;
  settings: InvestigationMatrixSettings;
  onSettingsChange: InvestigationMatrixSettingsChange;
  onSecurityPlatformsChange: (platforms: EntityOption[]) => void;
  isEmpty: boolean;
  hasScores: boolean;
  heatmapOn: boolean;
  heatMax: number;
  /** Why the heatmap cannot turn on when there is a more precise reason than no score at all (the filters). */
  heatmapDisabledReason?: string;
  exportName: string;
  /** The filter buttons, in the filters group. */
  filterActions?: ToolbarAction<MatrixToolbarGroup>[];
  /** The time range panel, under the row while it is open. */
  timeRangePanel?: ReactNode;
}

const MAX_LISTED_NAMES = 10;
const KILL_CHAIN_WIDTH = 180;
const POSTURE_WIDTH = 300;
const ICON = { fontSize: 'medium' } as const;
const NO_FILTER_ACTIONS: ToolbarAction<MatrixToolbarGroup>[] = [];

/**
 * The toolbar of the investigation matrix view, docked under it like the graph's: what the matrix
 * leaves out, the kill chain and the display, the heatmap and its legend, then the filters, the
 * security posture and the image export, which leave for "More actions" when the row has no room.
 * The graph-only tools (zoom, layout, selection, creation, search) have nothing to act on here.
 */
const InvestigationMatrixToolbar = ({
  outsideKillChain,
  killChains,
  killChain,
  settings,
  onSettingsChange,
  onSecurityPlatformsChange,
  isEmpty,
  hasScores,
  heatmapOn,
  heatMax,
  heatmapDisabledReason,
  exportName,
  filterActions = NO_FILTER_ACTIONS,
  timeRangePanel,
}: InvestigationMatrixToolbarProps) => {
  const { t_i18n } = useFormatter();
  const canExport = useGranted([KNOWLEDGE_KNFRONTENDEXPORT]);
  const { options, exporting, exportImage } = useMatrixImageExport({ elementId: INVESTIGATION_MATRIX_EXPORT_ID, name: exportName });
  const { onlyUsed, securityPlatforms } = settings;

  const postureLabel = t_i18n('Compare with my security posture');
  // The same field in the row and in the "More actions" submenu: its value lives in the settings.
  const postureSelect = () => (
    <div style={{ width: POSTURE_WIDTH }}>
      <EntitySelect
        multiple
        inline
        disabled={isEmpty}
        value={securityPlatforms}
        label={postureLabel}
        types={['SecurityPlatform']}
        onChange={(platforms) => onSecurityPlatformsChange(platforms as EntityOption[])}
      />
    </div>
  );

  const actions: ToolbarAction<MatrixToolbarGroup>[] = [
    ...filterActions,
    {
      id: 'posture',
      group: 'posture',
      priority: 20,
      // The field and the toolbar gap after it, until measured.
      width: POSTURE_WIDTH + TOOLBAR_GAP_PX,
      label: postureLabel,
      icon: <SecurityOutlined {...ICON} />,
      // The same field in the row and, by default, in the "More actions" submenu.
      render: postureSelect,
    },
  ];
  if (canExport) {
    actions.push({
      id: 'export-image',
      group: 'export',
      priority: 10,
      label: t_i18n('Export to image'),
      icon: <ImageOutlined {...ICON} />,
      // One capture at a time: a second one would swap the export theme under the first.
      disabledReason: exporting ? t_i18n('Export in progress') : undefined,
      options: {
        items: options,
        onSelect: (key) => {
          exportImage(key);
        },
      },
    });
  }

  const onlyUsedLabel = onlyUsed ? t_i18n('Display the whole matrix') : t_i18n('Display only used techniques');
  let heatmapReason: string | undefined;
  if (!hasScores) heatmapReason = heatmapDisabledReason ?? t_i18n('No attack pattern is linked to an entity in this investigation');

  const layout: ToolbarSlot<MatrixToolbarGroup>[] = [
    ...(outsideKillChain.length > 0 ? [
      {
        kind: 'pinned' as const,
        key: 'not-shown',
        render: () => (
          <Tooltip>
            <TooltipTrigger asChild>
              {/* Focusable, so the list of what is left out can be read from the keyboard too. */}
              <Text variant="content-compact" tabIndex={0} style={{ whiteSpace: 'nowrap' }}>
                {t_i18n(
                  '{count, plural, one {# attack pattern not shown} other {# attack patterns not shown}}',
                  { values: { count: outsideKillChain.length } },
                )}
              </Text>
            </TooltipTrigger>
            <TooltipContent side="top">
              {t_i18n('Outside the selected kill chain ({count})', { values: { count: outsideKillChain.length } })}
              <br />
              {formatNameList(outsideKillChain.map(formatAttackPatternLabel), MAX_LISTED_NAMES, t_i18n)}
            </TooltipContent>
          </Tooltip>
        ),
      },
      { kind: 'pinned' as const, key: 'not-shown-divider', render: () => <GroupDivider /> },
    ] : []),
    {
      kind: 'pinned',
      key: 'display',
      label: t_i18n('Display'),
      render: () => (
        <>
          <div style={{ width: KILL_CHAIN_WIDTH }}>
            <Select value={killChain ?? ''} onValueChange={(value) => onSettingsChange({ killChain: value })} disabled={isEmpty}>
              <SelectTrigger aria-label={t_i18n('Kill chain')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Kill chain')}>
                {killChains.map((killChainName) => (
                  <SelectItem key={killChainName} value={killChainName}>
                    {killChainName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <GraphToolbarItem
            title={onlyUsedLabel}
            Icon={<Icon name="eye" />}
            pressed={onlyUsed}
            disabled={isEmpty}
            onClick={() => onSettingsChange({ onlyUsed: !onlyUsed })}
          />
        </>
      ),
    },
    { kind: 'pinned', key: 'heatmap-divider', render: () => <GroupDivider /> },
    {
      kind: 'pinned',
      key: 'heatmap',
      label: t_i18n('Heatmap'),
      render: () => (
        <>
          <GraphToolbarItem
            title={t_i18n('Displays heat map of attack pattern use')}
            Icon={<LocalFireDepartmentOutlined {...ICON} />}
            pressed={heatmapOn}
            disabledReason={heatmapReason}
            onClick={() => onSettingsChange({ heatmap: !heatmapOn })}
          />
          {heatmapOn && <HeatmapLegend max={heatMax} />}
        </>
      ),
    },
    { kind: 'group', group: 'filters' },
    { kind: 'group', group: 'posture' },
    { kind: 'group', group: 'export' },
  ];

  return (
    <ToolbarShell<MatrixToolbarGroup>
      label={t_i18n('Matrix toolbar')}
      layout={layout}
      actions={actions}
      groups={MATRIX_TOOLBAR_GROUPS}
      groupLabels={{
        filters: t_i18n('Filters'),
        posture: t_i18n('Security posture'),
        export: t_i18n('Export'),
      }}
      pushMoreActionsRight
      height={timeRangePanel ? GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE : GRAPH_TOOLBAR_HEIGHT}
      progress={exporting}
      below={timeRangePanel}
    />
  );
};

export default InvestigationMatrixToolbar;
