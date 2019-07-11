/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { CSVLink } from 'react-csv';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles/index';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import CircularProgress from '@material-ui/core/CircularProgress';
import { SaveAlt } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = () => ({
  export: {
    width: '100%',
    paddingTop: 10,
    textAlign: 'center',
  },
  loaderCircle: {
    display: 'inline-block',
  },
});

class StixDomainEntitiesExportData extends Component {
  constructor(props) {
    super(props);
    this.state = { anchor: null, openExportCsv: false };
  }

  handleOpen(event) {
    this.setState({ anchor: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchor: null });
  }

  handleOpenExportCsv() {
    this.handleClose();
    this.props.handleGenerateCSV();
    this.setState({ openExportCsv: true });
  }

  handleCloseExportCsv() {
    this.setState({ openExportCsv: false });
  }

  render() {
    const {
      csvData, fileName, t, classes,
    } = this.props;

    return (
      <div style={{ display: 'inline-block' }}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          color="primary"
        >
          <SaveAlt />
        </IconButton>
        <Menu
          anchorEl={this.state.anchor}
          open={Boolean(this.state.anchor)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}
        >
          <MenuItem onClick={this.handleOpenExportCsv.bind(this)}>
            {t('CSV file')}
          </MenuItem>
        </Menu>
        <Dialog
          open={this.state.openExportCsv}
          onClose={this.handleCloseExportCsv.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Export data in CSV')}</DialogTitle>
          <DialogContent>
            {csvData === null ? (
              <div className={classes.export}>
                <CircularProgress
                  size={40}
                  thickness={2}
                  className={classes.loaderCircle}
                />
              </div>
            ) : (
              <DialogContentText>
                {t(
                  'The CSV file has been generated with the parameters of the view and is ready for download.',
                )}
              </DialogContentText>
            )}
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseExportCsv.bind(this)}
              color="primary"
            >
              {t('Cancel')}
            </Button>
            {csvData !== null ? (
              <Button
                component={CSVLink}
                data={csvData}
                separator={';'}
                enclosingCharacter={'"'}
                color="primary"
                filename={`${t(fileName)}.csv`}
              >
                {t('Download')}
              </Button>
            ) : (
              ''
            )}
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixDomainEntitiesExportData.propTypes = {
  classes: PropTypes.object,
  fileName: PropTypes.string,
  handleGenerateCSV: PropTypes.func,
  csvData: PropTypes.array,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntitiesExportData);
