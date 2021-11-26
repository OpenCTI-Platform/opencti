import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withTheme, withStyles } from '@material-ui/core/styles';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import {
  CheckCircleOutlined,
  CancelOutlined,
  DeleteOutlined,
} from '@material-ui/icons';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1100,
    padding: '0 0 0 180px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithPadding: {
    zIndex: 1100,
    padding: '0 230px 0 180px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  title: {
    flex: '1 1 100%',
    fontSize: '12px',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class PendingFileToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = { displayDelete: false };
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  render() {
    const {
      t,
      classes,
      numberOfSelectedElements,
      handleValidate,
      handleDrop,
      withPaddingRight,
      theme,
      isDeleteActive,
    } = this.props;
    const { displayDelete } = this.state;
    return (
      <Drawer
        anchor="bottom"
        variant="persistent"
        classes={{
          paper: withPaddingRight
            ? classes.bottomNavWithPadding
            : classes.bottomNav,
        }}
        open={true}
      >
        <Toolbar style={{ minHeight: 54 }}>
          <Typography
            className={classes.title}
            color="inherit"
            variant="subtitle1"
          >
            <span
              style={{
                padding: '2px 5px 2px 5px',
                marginRight: 5,
                backgroundColor: theme.palette.secondary.main,
                color: '#ffffff',
              }}
            >
              {numberOfSelectedElements}
            </span>{' '}
            {t('selected')}
          </Typography>
          <Tooltip title={t('Validate this pending bundle')}>
            <span>
              <IconButton
                aria-label="validate"
                onClick={handleValidate.bind(this)}
                color="primary"
                disabled={isDeleteActive}
              >
                <CheckCircleOutlined />
              </IconButton>
            </span>
          </Tooltip>
          {isDeleteActive ? (
            <Tooltip title={t('Delete this pending bundle')}>
              <span>
                <IconButton
                  aria-label="drop"
                  onClick={this.handleOpenDelete.bind(this)}
                  color="primary"
                >
                  <DeleteOutlined />
                </IconButton>
              </span>
            </Tooltip>
          ) : (
            <Tooltip title={t('Drop this pending bundle')}>
              <span>
                <IconButton
                  aria-label="drop"
                  onClick={this.handleOpenDelete.bind(this)}
                  color="primary"
                >
                  <CancelOutlined />
                </IconButton>
              </span>
            </Tooltip>
          )}
        </Toolbar>
        <Dialog
          open={displayDelete}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {isDeleteActive
                ? t('Do you want to delete this bundle?')
                : t('Do you want to drop this bundle?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseDelete.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button onClick={handleDrop.bind(this)} color="primary">
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </Drawer>
    );
  }
}

PendingFileToolBar.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  numberOfSelectedElements: PropTypes.number,
  handleOpenValidate: PropTypes.func,
  handleOpenDrop: PropTypes.func,
  isDeleteActive: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(PendingFileToolBar);
