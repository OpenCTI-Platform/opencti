import ApexCharts, { ApexOptions } from 'apexcharts';
import React, { CSSProperties, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { FileDownloadOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';

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
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);

  const handleExportToSVG = () => {
    setAnchorEl(null);
    if (chart) chart.exports.exportToSVG();
  };

  const handleExportToPng = () => {
    setAnchorEl(null);
    if (chart) chart.exports.exportToPng();
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

  const styleContainer: CSSProperties = {
    margin: 0,
    top: 0,
    right: isReadOnly ? 0 : 32,
    position: 'absolute',
  };

  return (
    <div style={styleContainer}>
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
        keepMounted
        className="noDrag"
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem onClick={handleExportToPng}>{t_i18n('Download as PNG')}</MenuItem>
        <MenuItem onClick={handleExportToSVG}>{t_i18n('Download as SVG')}</MenuItem>
        <MenuItem onClick={handleExportToCSV}>{t_i18n('Download as CSV')}</MenuItem>
      </Menu>
    </div>
  );
};

export default ExportPopover;
