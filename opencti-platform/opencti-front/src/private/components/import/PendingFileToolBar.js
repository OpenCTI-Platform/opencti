import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import {
  CheckCircleOutlined,
  CancelOutlined,
  DeleteOutlined,
} from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import inject18n from '../../../components/i18n';

const styles = () => ({
  bottomNav: {
    zIndex: 1100,
    padding: '0 0 0 180px',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithPadding: {
    zIndex: 1100,
    padding: '0 230px 0 180px',
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
        PaperProps={{ variant: 'elevation', elevation: 1 }}
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
                color="secondary"
                disabled={isDeleteActive}
                size="large"
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
                  size="large"
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
                  size="large"
                >
                  <CancelOutlined />
                </IconButton>
              </span>
            </Tooltip>
          )}
        </Toolbar>
        <Dialog
          open={displayDelete}
          PaperProps={{ elevation: 1 }}
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
            <Button onClick={handleDrop.bind(this)} color="secondary">
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
