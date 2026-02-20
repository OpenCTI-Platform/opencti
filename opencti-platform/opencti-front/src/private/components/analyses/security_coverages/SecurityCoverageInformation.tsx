import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import {
  Avatar,
  Box,
  FormControl,
  MenuItem,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { ViewListOutlined, CompareArrowsOutlined } from '@mui/icons-material';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import { useFormatter } from '../../../../components/i18n';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';
import { donutChartOptions } from '../../../../utils/Charts';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles((theme: Theme) => ({
  charts: {
    display: 'flex',
    gap: theme.spacing(3),
    flexWrap: 'wrap',
  },
  chartItem: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: theme.spacing(1),
  },
  chart: {
    position: 'absolute',
    top: -5,
    left: -5,
  },
  chartContainer: {
    position: 'relative',
    overflow: 'hidden',
    width: 60,
    height: 60,
    padding: 4,
  },
  iconOverlay: {
    fontSize: 24,
    position: 'absolute',
    top: 22,
    left: 22,
  },
  scoreText: {
    fontSize: 14,
    fontWeight: 600,
    color: theme.palette.text?.primary || '#ffffff',
  },
  coverageName: {
    fontSize: 12,
    color: theme.palette.text?.secondary || '#999999',
    textAlign: 'center',
  },
  orgSelector: {
    marginBottom: theme.spacing(2),
  },
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: theme.spacing(2),
  },
  aggregateRow: {
    backgroundColor: theme.palette.background.default,
    fontWeight: 600,
  },
}));

// Flat score format (used by StixCoreRelationship coverage_information)
interface CoverageScore {
  readonly coverage_name: string;
  readonly coverage_score: number;
}

// Org-scoped result format (v2, used by SecurityCoverage entity)
export interface OrganizationCoverageResultData {
  readonly organization_id: string;
  readonly organization_name: string;
  readonly last_result: string | null;
  readonly auto_enrichment: boolean | null | undefined;
  readonly results: ReadonlyArray<CoverageScore>;
}

// The component accepts either flat scores OR org-scoped results
type CoverageInformationData = ReadonlyArray<CoverageScore | OrganizationCoverageResultData>;

interface SecurityCoverageInformationProps {
  coverage_information: CoverageInformationData | null | undefined;
  variant?: 'header' | 'details' | 'matrix';
}

// Type guard: check if data is org-scoped (has organization_id)
const isOrgScoped = (item: CoverageScore | OrganizationCoverageResultData): item is OrganizationCoverageResultData => {
  return 'organization_id' in item && 'results' in item;
};

// Helper: get score color
const getScoreColor = (score: number, theme: Theme) => {
  const warningColor = (theme.palette as { warning?: { main: string } }).warning?.main;
  if (score >= 70) return theme.palette.success.main;
  if (score >= 40) return warningColor || theme.palette.primary.main;
  return theme.palette.error.main;
};

// Compare table sub-component
const CoverageCompareTable: FunctionComponent<{
  orgResults: ReadonlyArray<OrganizationCoverageResultData>;
}> = ({ orgResults }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();

  // Collect all unique metric names across all orgs
  const allMetricNames = Array.from(
    new Set(orgResults.flatMap((org) => org.results.map((r) => r.coverage_name))),
  );

  // Build a lookup: orgId -> metricName -> score
  const scoreMap = new Map<string, Map<string, number>>();
  for (const org of orgResults) {
    const metricMap = new Map<string, number>();
    for (const r of org.results) {
      metricMap.set(r.coverage_name, r.coverage_score);
    }
    scoreMap.set(org.organization_id, metricMap);
  }

  // Compute aggregates per metric
  const aggregates = allMetricNames.map((metricName) => {
    const values = orgResults
      .map((org) => scoreMap.get(org.organization_id)?.get(metricName))
      .filter((v): v is number => v !== undefined);
    const avg = values.length > 0 ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : null;
    const min = values.length > 0 ? Math.min(...values) : null;
    const max = values.length > 0 ? Math.max(...values) : null;
    return { metricName, avg, min, max };
  });

  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Metric')}</TableCell>
            {orgResults.map((org) => (
              <TableCell key={org.organization_id} align="center" sx={{ fontWeight: 600 }}>
                {org.organization_name}
              </TableCell>
            ))}
            <TableCell align="center" sx={{ fontWeight: 600 }}>{t_i18n('Avg')}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {allMetricNames.map((metricName) => {
            const agg = aggregates.find((a) => a.metricName === metricName);
            return (
              <TableRow key={metricName}>
                <TableCell component="th" scope="row">{metricName}</TableCell>
                {orgResults.map((org) => {
                  const score = scoreMap.get(org.organization_id)?.get(metricName);
                  return (
                    <TableCell key={org.organization_id} align="center">
                      {score !== undefined ? (
                        <span style={{ color: getScoreColor(score, theme), fontWeight: 600 }}>
                          {score}%
                        </span>
                      ) : (
                        <span style={{ color: theme.palette.text?.disabled }}>--</span>
                      )}
                    </TableCell>
                  );
                })}
                <TableCell align="center">
                  {agg?.avg !== null ? (
                    <Tooltip title={`Min: ${agg?.min}% — Max: ${agg?.max}%`}>
                      <span style={{ color: getScoreColor(agg!.avg!, theme), fontWeight: 600 }}>
                        {agg?.avg}%
                      </span>
                    </Tooltip>
                  ) : '--'}
                </TableCell>
              </TableRow>
            );
          })}
          {/* Footer row: last result + mode */}
          <TableRow className={classes.aggregateRow}>
            <TableCell component="th" scope="row">{t_i18n('Last result')}</TableCell>
            {orgResults.map((org) => (
              <TableCell key={org.organization_id} align="center">
                <Typography variant="caption">
                  {org.last_result ? new Date(org.last_result).toLocaleDateString() : '--'}
                </Typography>
              </TableCell>
            ))}
            <TableCell />
          </TableRow>
          <TableRow className={classes.aggregateRow}>
            <TableCell component="th" scope="row">{t_i18n('Mode')}</TableCell>
            {orgResults.map((org) => (
              <TableCell key={org.organization_id} align="center">
                <Typography variant="caption">
                  {org.auto_enrichment ? t_i18n('Auto') : t_i18n('Manual')}
                </Typography>
              </TableCell>
            ))}
            <TableCell />
          </TableRow>
          {/* Aggregate summary row */}
          <TableRow sx={{ '& td': { borderTop: 2, borderColor: 'divider' } }}>
            <TableCell component="th" scope="row" sx={{ fontWeight: 600 }}>
              {t_i18n('Min / Max')}
            </TableCell>
            {orgResults.map((org) => (
              <TableCell key={org.organization_id} />
            ))}
            <TableCell align="center">
              <Typography variant="caption" color="textSecondary">
                {aggregates.map((a) => (
                  <div key={a.metricName}>
                    {a.metricName}: {a.min ?? '--'}% / {a.max ?? '--'}%
                  </div>
                ))}
              </Typography>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </TableContainer>
  );
};

const SecurityCoverageInformation: FunctionComponent<SecurityCoverageInformationProps> = ({ coverage_information, variant = 'header' }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const [selectedOrgIndex, setSelectedOrgIndex] = useState(0);
  const [viewMode, setViewMode] = useState<'single' | 'compare'>('single');

  const genOpts = (score: number | null) => {
    let chartColors = [theme.palette.action?.disabled ?? '#ffffff'];
    let labels = [t_i18n('Unknown')];
    let series = [score ?? 100];
    if (isNotEmptyField(score)) {
      chartColors = [theme.palette.success.main ?? '', theme.palette.error.main ?? ''];
      labels = [t_i18n('Success'), t_i18n('Failure')];
      series = [score, 100 - score];
    }
    const options = donutChartOptions(
      theme,
      labels,
      'bottom',
      false,
      chartColors,
      false,
      false,
      true,
      false,
      65,
      false,
    ) as ApexOptions;
    return { series, options };
  };

  // Normalize data: determine if org-scoped or flat
  const rawData = coverage_information ?? [];
  const firstItem = rawData[0];
  const isOrgScopedData = firstItem && isOrgScoped(firstItem);

  // Extract scores and org metadata
  let scores: ReadonlyArray<CoverageScore>;
  let orgResults: ReadonlyArray<OrganizationCoverageResultData> = [];
  let selectedOrg: OrganizationCoverageResultData | null = null;
  let hasMultipleOrgs = false;

  if (isOrgScopedData) {
    orgResults = rawData as ReadonlyArray<OrganizationCoverageResultData>;
    selectedOrg = orgResults[selectedOrgIndex] ?? orgResults[0] ?? null;
    scores = selectedOrg?.results ?? [];
    hasMultipleOrgs = orgResults.length > 1;
  } else {
    scores = rawData as ReadonlyArray<CoverageScore>;
  }

  // Header or matrix variant (compact) — show donuts without org selector
  if (variant === 'header' || variant === 'matrix') {
    const size = variant === 'matrix' ? 28 : 40;
    const chartSize = variant === 'matrix' ? 38 : 50;
    const iconSize = variant === 'matrix' ? 12 : 18;
    const iconPosition = variant === 'matrix' ? 13 : 16;
    if (isEmptyField(scores) || scores.length === 0) {
      const { options, series } = genOpts(null);
      return (
        <div className={classes.chartContainer} style={{ width: size, height: size }}>
          <div className={classes.chart}>
            <Chart options={options} series={series} type="donut" width={chartSize} height={chartSize} />
            <Tooltip title="Empty coverage" placement="bottom">
              <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: iconSize, height: iconSize }} style={{ top: iconPosition, left: iconPosition, fontSize: iconSize - 2 }}>
                <span style={{ color: theme.palette.text?.primary }}>E</span>
              </Avatar>
            </Tooltip>
          </div>
        </div>
      );
    }
    return (
      <div style={{ display: 'flex' }}>
        {scores.map((coverageResult) => {
          const { options, series } = genOpts(coverageResult.coverage_score);
          const tooltipPrefix = selectedOrg ? `${selectedOrg.organization_name} — ` : '';
          return (
            <div key={coverageResult.coverage_name} className={classes.chartContainer} style={{ width: size, height: size, padding: variant === 'matrix' ? 2 : 4 }}>
              <div className={classes.chart}>
                <Chart options={options} series={series} type="donut" width={chartSize} height={chartSize} />
                <Tooltip title={`${tooltipPrefix}${coverageResult.coverage_name} ${coverageResult.coverage_score}/100`} placement="bottom">
                  <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: iconSize, height: iconSize }} style={{ top: iconPosition, left: iconPosition, fontSize: iconSize - 2 }}>
                    <span style={{ color: theme.palette.text?.primary }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
                  </Avatar>
                </Tooltip>
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  // Details variant — empty state
  if (!isOrgScopedData && (isEmptyField(scores) || scores.length === 0)) {
    const { options, series } = genOpts(null);
    return (
      <div className={classes.charts}>
        <div className={classes.chartItem}>
          <div className={classes.chartContainer}>
            <div className={classes.chart}>
              <Chart options={options} series={series} type="donut" width={70} height={70} />
              <Tooltip title="Empty coverage" placement="top">
                <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 24, height: 24 }}>
                  <span style={{ color: theme.palette.text?.primary, fontSize: 18 }}>E</span>
                </Avatar>
              </Tooltip>
            </div>
          </div>
          <div className={classes.scoreText}>--%</div>
          <div className={classes.coverageName}>{t_i18n('Empty coverage')}</div>
        </div>
      </div>
    );
  }

  // Details variant — with optional Compare toggle
  return (
    <div>
      {/* Toolbar: org selector (single mode) or toggle (multi-org) */}
      {hasMultipleOrgs && (
        <Box className={classes.toolbar}>
          {viewMode === 'single' && (
            <FormControl size="small">
              <Select
                value={selectedOrgIndex}
                onChange={(e) => setSelectedOrgIndex(e.target.value as number)}
                variant="outlined"
                size="small"
              >
                {orgResults.map((org, index) => (
                  <MenuItem key={org.organization_id} value={index}>
                    {org.organization_name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          {viewMode === 'compare' && (
            <Typography variant="body2" color="textSecondary">
              {t_i18n('All organizations')} ({orgResults.length})
            </Typography>
          )}
          <ToggleButtonGroup
            size="small"
            value={viewMode}
            exclusive
            onChange={(_, value) => value && setViewMode(value)}
            sx={{
              height: 30,
              '& .MuiToggleButton-root': {
                padding: '4px 10px',
                fontSize: 12,
                '&.Mui-selected': {
                  backgroundColor: 'primary.main',
                  color: 'primary.contrastText',
                  '&:hover': { backgroundColor: 'primary.dark' },
                },
              },
            }}
          >
            <ToggleButton value="single">
              <ViewListOutlined fontSize="small" sx={{ mr: 0.5 }} />
              {t_i18n('Single')}
            </ToggleButton>
            <ToggleButton value="compare">
              <CompareArrowsOutlined fontSize="small" sx={{ mr: 0.5 }} />
              {t_i18n('Compare')}
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
      )}
      {/* Single org name when only one org */}
      {isOrgScopedData && !hasMultipleOrgs && selectedOrg && (
        <Typography variant="body2" color="textSecondary" style={{ marginBottom: 8 }}>
          {selectedOrg.organization_name}
        </Typography>
      )}

      {/* Compare mode: side-by-side table */}
      {viewMode === 'compare' && hasMultipleOrgs && (
        <CoverageCompareTable orgResults={orgResults} />
      )}

      {/* Single mode: donut charts for selected org */}
      {viewMode === 'single' && (
        <>
          <div className={classes.charts}>
            {scores.map((coverageResult) => {
              const scoreColor = getScoreColor(coverageResult.coverage_score, theme);
              const { options, series } = genOpts(coverageResult.coverage_score);
              return (
                <div key={coverageResult.coverage_name} className={classes.chartItem}>
                  <div className={classes.chartContainer}>
                    <div className={classes.chart}>
                      <Chart options={options} series={series} type="donut" width={70} height={70} />
                      <Tooltip title={coverageResult.coverage_name} placement="top">
                        <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 24, height: 24 }}>
                          <span style={{ color: theme.palette.text?.primary, fontSize: 18 }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
                        </Avatar>
                      </Tooltip>
                    </div>
                  </div>
                  <div className={classes.scoreText} style={{ color: scoreColor }}>
                    {coverageResult.coverage_score}%
                  </div>
                  <div className={classes.coverageName}>
                    {coverageResult.coverage_name}
                  </div>
                </div>
              );
            })}
          </div>
          {selectedOrg?.last_result && (
            <Typography variant="caption" color="textSecondary" style={{ marginTop: 8, display: 'block' }}>
              {t_i18n('Last result')}: {new Date(selectedOrg.last_result).toLocaleDateString()}
              {selectedOrg.auto_enrichment ? ` — ${t_i18n('Auto')}` : ''}
            </Typography>
          )}
        </>
      )}
    </div>
  );
};

export default SecurityCoverageInformation;
