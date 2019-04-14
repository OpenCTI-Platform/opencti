import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import CircularProgress from '@material-ui/core/CircularProgress';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import StixDomainEntityExportContent, {
  stixDomainEntityExportContentQuery,
} from './StixDomainEntityExportContent';

const styles = () => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
  export: {
    width: '100%',
    paddingTop: 10,
    textAlign: 'center',
  },
  loaderCircle: {
    display: 'inline-block',
  },
});

function Transition(props) {
  return <Slide direction="up" {...props} />;
}

class StixDomainEntityExport extends Component {
  render() {
    const {
      t,
      classes,
      stixDomainEntityId,
      stixDomainEntityType,
      handleClose,
      open,
    } = this.props;
    return (
      <Dialog
        open={open}
        fullWidth={true}
        TransitionComponent={Transition}
        onClose={handleClose.bind(this)}
      >
        <DialogTitle>{t('Export the entity')}</DialogTitle>
        <DialogContent>
          <QueryRenderer
            query={stixDomainEntityExportContentQuery}
            variables={{
              id: stixDomainEntityId,
              types: ['export.stix2.simple', 'export.stix2.full'],
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainEntityExportContent
                    stixDomainEntity={props.stixDomainEntity}
                    stixDomainEntityType={stixDomainEntityType}
                    handleClose={handleClose.bind(this)}
                  />
                );
              }
              return (
                <div className={classes.export}>
                  <CircularProgress
                    size={40}
                    thickness={2}
                    className={classes.loaderCircle}
                  />
                </div>
              );
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose.bind(this)} color="primary">
            {t('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    );
  }
}

StixDomainEntityExport.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  stixDomainEntityId: PropTypes.string,
  stixDomainEntityType: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityExport);
