import React, { useState } from 'react';
import ApexChart, { Props as ApexProps } from 'react-apexcharts';
import ApexCharts, { ApexOptions } from 'apexcharts';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { FileDownloadOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    top: 0,
    right: 32,
    position: 'absolute',
  },
  containerReadOnly: {
    margin: 0,
    top: 0,
    right: 0,
    position: 'absolute',
  },
}));

interface ExportPopoverProps {
  chart?: ApexCharts;
  series?: ApexOptions['series'];
  isReadOnly?: boolean;
}

const ExportPopover = ({
  chart,
  isReadOnly,
  series,
}: ExportPopoverProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);

  const handleExportToSVG = () => {
    setAnchorEl(null);
    if (chart) {
      chart.exports.exportToSVG();
    }
  };

  const handleExportToPng = () => {
    setAnchorEl(null);
    if (chart) {
      chart.exports.exportToPng();
    }
  };

  const handleExportToCSV = () => {
    setAnchorEl(null);
    if (chart) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const currentFormatter = chart.opts.xaxis?.labels?.formatter;
      if (currentFormatter) {
        chart.updateOptions({ xaxis: { labels: { formatter: (value: string) => value } } }, false, false, false);
        chart.exports.exportToCSV({ series });
        chart.updateOptions({ xaxis: { labels: { formatter: currentFormatter } } }, false);
      } else {
        chart.exports.exportToCSV({ series });
      }
    }
  };

  return (
    <div className={isReadOnly ? classes.containerReadOnly : classes.container}>
      <IconButton
        onClick={(event) => {
          event.stopPropagation();
          event.preventDefault();
          setAnchorEl(event.currentTarget);
        }}
        aria-haspopup="true"
        size="small"
        className="noDrag"
        color="primary"
      >
        <FileDownloadOutlined fontSize="small" />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        keepMounted={true}
        onClose={() => setAnchorEl(null)}
        className="noDrag"
      >
        <MenuItem onClick={handleExportToPng}>{t_i18n('Download as PNG')}</MenuItem>
        <MenuItem onClick={handleExportToSVG}>{t_i18n('Download as SVG')}</MenuItem>
        <MenuItem onClick={handleExportToCSV}>{t_i18n('Download as CSV')}</MenuItem>
      </Menu>
    </div>
  );
};

interface OpenCTIChartProps extends ApexProps {
  withExportPopover?: boolean;
  isReadOnly?: boolean;
}

const Chart = ({
  options,
  series,
  type,
  width,
  height,
  withExportPopover,
  isReadOnly,
}: OpenCTIChartProps) => {
  const [chart, setChart] = useState<ApexCharts>();

  // Add in config a callback on 'mounted event' to retrieve chart context.
  // This context is used to export in different format.
  const apexOptions: ApexProps['options'] = {
    ...options,
    chart: {
      ...options?.chart,
      events: {
        ...options?.chart?.events,
        mounted(c) {
          setChart(c);
        },
      },
    },
  };

  return (
    <>
      <ApexChart
        options={apexOptions}
        series={series}
        type={type}
        width={width}
        height={height}
      />
      {withExportPopover === true && (
        <ExportPopover
          chart={chart}
          series={series}
          isReadOnly={isReadOnly}
        />
      )}
    </>
  );
};

export default Chart;
