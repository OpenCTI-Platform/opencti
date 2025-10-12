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

const useStyles = makeStyles(() => ({
  charts: {
    display: 'flex',
  },
  chart: {
    position: 'absolute',
    top: -5,
    left: -5,
  },
  chartContainer: {
    position: 'relative',
    overflow: 'hidden',
    width: 40,
    height: 40,
    padding: 4,
  },
  iconOverlay: {
    fontSize: 18,
    position: 'absolute',
    top: 16,
    left: 16,
  },
}));

interface SecurityCoverageInformationProps {
  coverage_information: ReadonlyArray<{
    readonly coverage_name: string;
    readonly coverage_score: number;
  }> | null | undefined;
}

const SecurityCoverageInformation: FunctionComponent<SecurityCoverageInformationProps> = ({ coverage_information }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();
  if (isEmptyField(coverage_information)) {
    return <span>-</span>;
  }
  return (
    <div className={classes.charts}>
      {(coverage_information ?? []).map((coverageResult) => {
        let chartColors = [theme.palette.action?.disabled ?? '#ffffff'];
        let labels = [t_i18n('Unknown')];
        let series = [coverageResult.coverage_score];
        if (isNotEmptyField(coverageResult.coverage_score)) {
          chartColors = [theme.palette.success.main ?? '', theme.palette.error.main ?? ''];
          labels = [t_i18n('Success'), t_i18n('Failure')];
          series = [coverageResult.coverage_score, 100 - coverageResult.coverage_score];
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
        return <div key={coverageResult.coverage_name} className={classes.chartContainer}>
          <div className={classes.chart}>
            <Chart options={options} series={series} type="donut" width={50} height={50}/>
            <Tooltip title={`${t_i18n(coverageResult.coverage_name)}`} placement="bottom">
              <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 18, height: 18 }}>
                <span style={{ color: '#ffffff' }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
              </Avatar>
            </Tooltip>
          </div>
        </div>;
      })}
    </div>
  );
};

export default SecurityCoverageInformation;
