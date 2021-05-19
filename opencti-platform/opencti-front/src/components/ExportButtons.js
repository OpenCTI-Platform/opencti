import React from 'react';
import IconButton from '@material-ui/core/IconButton';
import { ImageOutlined } from '@material-ui/icons';
import { FilePdfOutline } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import { withStyles } from '@material-ui/core/styles';
import * as R from 'ramda';
import { exportImage, exportPdf } from '../utils/Image';
import inject18n from './i18n';

const styles = () => ({
  exportButtons: {
    display: 'flex',
  },
});

const ExportButtons = (props) => {
  const {
    classes, domElementId, name, t,
  } = props;
  return (
    <div className={classes.exportButtons}>
      <Tooltip title={t('Export to image (png)')} aria-label="generate-export">
        <span>
          <IconButton
            onClick={() => exportImage(domElementId, name)}
            color="primary"
            aria-label="Export"
          >
            <ImageOutlined />
          </IconButton>
        </span>
      </Tooltip>
      <Tooltip
        title={t('Export to document (pdf)')}
        aria-label="generate-export"
      >
        <span>
          <IconButton
            onClick={() => exportPdf(domElementId, name)}
            color="primary"
            aria-label="Export"
          >
            <FilePdfOutline />
          </IconButton>
        </span>
      </Tooltip>
    </div>
  );
};

export default R.compose(inject18n, withStyles(styles))(ExportButtons);
