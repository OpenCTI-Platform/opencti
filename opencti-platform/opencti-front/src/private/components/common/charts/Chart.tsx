import React, { RefObject, useRef, useState } from 'react';
import ApexChart, { Props } from 'react-apexcharts';
import type ReactApexChart from 'react-apexcharts';
import ApexCharts, { ApexOptions } from 'apexcharts';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { FileDownloadOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    top: 0,
    right: 32,
    position: 'absolute',
  },
}));

interface ChartType extends ReactApexChart {
  chart: { ctx: ApexCharts };
}

interface ExportPopoverProps {
  chartRef: RefObject<ChartType>;
  series?: ApexOptions['series'];
}

const ExportPopover = ({ chartRef, series }: ExportPopoverProps) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);
  const handleExportToSVG = () => {
    setAnchorEl(null);
    if (chartRef.current) {
      chartRef.current.chart.ctx.exports.exportToSVG();
    }
  };
  const handleExportToPng = () => {
    setAnchorEl(null);
    if (chartRef.current) {
      chartRef.current.chart.ctx.exports.exportToPng();
    }
  };
  const handleExportToCSV = () => {
    setAnchorEl(null);
    if (chartRef.current) {
      chartRef.current.chart.ctx.exports.exportToCSV({ series });
    }
  };
  return (
    <div className={classes.container}>
      <IconButton
        onClick={(event) => {
          event.stopPropagation();
          event.preventDefault();
          setAnchorEl(event.currentTarget);
        }}
        aria-haspopup="true"
        size="small"
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
        <MenuItem onClick={handleExportToPng}>{t('Export png')}</MenuItem>
        <MenuItem onClick={handleExportToSVG}>{t('Export svg')}</MenuItem>
        <MenuItem onClick={handleExportToCSV}>{t('Export csv')}</MenuItem>
      </Menu>
    </div>
  );
};

interface OpenCTIChartProps extends Props {
  withExportPopover?: boolean;
}

const Chart = ({
  options,
  series,
  type,
  width,
  height,
  withExportPopover,
}: OpenCTIChartProps) => {
  const chartRef = useRef<ChartType>(null);
  return (
    <>
      <ApexChart
        ref={chartRef}
        options={options}
        series={series}
        type={type}
        width={width}
        height={height}
      />
      {withExportPopover === true && (
        <ExportPopover chartRef={chartRef} series={series} />
      )}
    </>
  );
};

export default Chart;
