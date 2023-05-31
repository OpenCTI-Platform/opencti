import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import { FileDownloadOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles((theme) => ({
  container: {
    margin: 0,
    top: 0,
    right: 32,
    position: 'absolute',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

const ExportPopover = ({ chartRef, chartData }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const handleExportToSVG = () => {
    setAnchorEl(null);
    chartRef.current.chart.ctx.exports.exportToSVG();
  };
  const handleExportToPng = () => {
    chartRef.current.chart.ctx.exports.exportToPng();
    setAnchorEl(null);
  };
  const handleExportToCSV = () => {
    chartRef.current.chart.ctx.exports.exportToCSV({ series: chartData });
    setAnchorEl(null);
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
        size="small">
        <FileDownloadOutlined fontSize="small" />
      </IconButton>
      <Menu anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        keepMounted={true}
        onClose={() => setAnchorEl(null)}
        className="noDrag">
          <MenuItem onClick={handleExportToPng}>{t('Export png')}</MenuItem>
          <MenuItem onClick={handleExportToSVG}>{t('Export svg')}</MenuItem>
          <MenuItem onClick={handleExportToCSV}>{t('Export csv')}</MenuItem>
      </Menu>
    </div>
  );
};

export default ExportPopover;
