import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { Avatar, Tooltip } from '@mui/material';
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
}));

interface SecurityCoverageInformationProps {
  coverage_information: ReadonlyArray<{
    readonly coverage_name: string;
    readonly coverage_score: number;
  }> | null | undefined;
  variant?: 'header' | 'details' | 'matrix';
}

const SecurityCoverageInformation: FunctionComponent<SecurityCoverageInformationProps> = ({ coverage_information, variant = 'header' }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();
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

  // Original variant for header or matrix (compact)
  if (variant === 'header' || variant === 'matrix') {
    const size = variant === 'matrix' ? 28 : 40;
    const chartSize = variant === 'matrix' ? 38 : 50;
    const iconSize = variant === 'matrix' ? 12 : 18;
    const iconPosition = variant === 'matrix' ? 13 : 16;
    if (isEmptyField(coverage_information)) {
      const { options, series } = genOpts(null);
      return <div className={classes.chartContainer} style={{ width: size, height: size }}>
        <div className={classes.chart}>
          <Chart options={options} series={series} type="donut" width={chartSize} height={chartSize}/>
          <Tooltip title={'Empty coverage'} placement="bottom">
            <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: iconSize, height: iconSize }} style={{ top: iconPosition, left: iconPosition, fontSize: iconSize - 2 }}>
              <span style={{ color: theme.palette.text?.primary }}>E</span>
            </Avatar>
          </Tooltip>
        </div>
      </div>;
    }
    return (
      <div style={{ display: 'flex' }}>
        {(coverage_information ?? []).map((coverageResult) => {
          const { options, series } = genOpts(coverageResult.coverage_score);
          return <div key={coverageResult.coverage_name} className={classes.chartContainer} style={{ width: size, height: size, padding: variant === 'matrix' ? 2 : 4 }}>
            <div className={classes.chart}>
              <Chart options={options} series={series} type="donut" width={chartSize} height={chartSize}/>
              <Tooltip title={`${coverageResult.coverage_name} ${coverageResult.coverage_score}/100`} placement="bottom">
                <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: iconSize, height: iconSize }} style={{ top: iconPosition, left: iconPosition, fontSize: iconSize - 2 }}>
                  <span style={{ color: theme.palette.text?.primary }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
                </Avatar>
              </Tooltip>
            </div>
          </div>;
        })}
      </div>
    );
  }

  // Details variant with scores
  if (isEmptyField(coverage_information)) {
    const { options, series } = genOpts(null);
    return (
      <div className={classes.charts}>
        <div className={classes.chartItem}>
          <div className={classes.chartContainer}>
            <div className={classes.chart}>
              <Chart options={options} series={series} type="donut" width={70} height={70}/>
              <Tooltip title={'Empty coverage'} placement="top">
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
  return (
    <div className={classes.charts}>
      {(coverage_information ?? []).map((coverageResult) => {
        const { options, series } = genOpts(coverageResult.coverage_score);
        const warningColor = (theme.palette as { warning?: { main: string } }).warning?.main;
        let scoreColor;
        if (coverageResult.coverage_score >= 70) {
          scoreColor = theme.palette.success.main;
        } else if (coverageResult.coverage_score >= 40) {
          scoreColor = warningColor || theme.palette.primary.main;
        } else {
          scoreColor = theme.palette.error.main;
        }
        return (
          <div key={coverageResult.coverage_name} className={classes.chartItem}>
            <div className={classes.chartContainer}>
              <div className={classes.chart}>
                <Chart options={options} series={series} type="donut" width={70} height={70}/>
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
  );
};

export default SecurityCoverageInformation;
