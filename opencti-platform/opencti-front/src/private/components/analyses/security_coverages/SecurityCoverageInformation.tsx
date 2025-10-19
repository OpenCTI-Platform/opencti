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
  variant?: 'header' | 'details';
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

  // Original variant for header
  if (variant === 'header') {
    if (isEmptyField(coverage_information)) {
      const { options, series } = genOpts(null);
      return <div className={classes.chartContainer} style={{ width: 40, height: 40 }}>
        <div className={classes.chart}>
          <Chart options={options} series={series} type="donut" width={50} height={50}/>
          <Tooltip title={'Empty coverage'} placement="bottom">
            <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 18, height: 18 }} style={{ top: 16, left: 16, fontSize: 18 }}>
              <span style={{ color: '#ffffff' }}>E</span>
            </Avatar>
          </Tooltip>
        </div>
      </div>;
    }
    return (
      <div style={{ display: 'flex' }}>
        {(coverage_information ?? []).map((coverageResult) => {
          const { options, series } = genOpts(coverageResult.coverage_score);
          return <div key={coverageResult.coverage_name} className={classes.chartContainer} style={{ width: 40, height: 40, padding: 4 }}>
            <div className={classes.chart}>
              <Chart options={options} series={series} type="donut" width={50} height={50}/>
              <Tooltip title={`${t_i18n(coverageResult.coverage_name)}`} placement="bottom">
                <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 18, height: 18 }} style={{ top: 16, left: 16, fontSize: 18 }}>
                  <span style={{ color: '#ffffff' }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
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
                  <span style={{ color: '#ffffff', fontSize: 18 }}>E</span>
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
                <Tooltip title={`${t_i18n(coverageResult.coverage_name)}`} placement="top">
                  <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 24, height: 24 }}>
                    <span style={{ color: '#ffffff', fontSize: 18 }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
                  </Avatar>
                </Tooltip>
              </div>
            </div>
            <div className={classes.scoreText} style={{ color: scoreColor }}>
              {coverageResult.coverage_score}%
            </div>
            <div className={classes.coverageName}>
              {t_i18n(coverageResult.coverage_name)}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default SecurityCoverageInformation;
