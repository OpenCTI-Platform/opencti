import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import { commitMutation as CM } from 'react-relay';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import { adaptFieldValue } from '../../../../../utils/String';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/SelectField';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { toastGenericError } from '../../../../../utils/bakedToast';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    margin: '10px 0',
    padding: '10px 0 20px 22px',
  },
  dialogRiskLevelAction: {
    textAlign: 'right',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  dialogRoot: {
    padding: '24px',
  },
  dialogContent: {
    overflowY: 'hidden',
  },
  menuItem: {
    padding: '15px 0',
    width: '170px',
    margin: '0 20px',
    justifyContent: 'center',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction='up' ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class EntitiesPartiesPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      deleting: false,
      isOpen: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget, isOpen: true });
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  render() {
    const {
      classes,
      t,
      history,
      node,
      nodeId,
      riskNode,
    } = this.props;
    return (
      <div className={classes.container}>
        <IconButton onClick={this.handleOpen.bind(this)} aria-haspopup='true'>
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}
        >
          <MenuItem
            className={classes.menuItem}
            // divider={true}
            // onClick={() => history.push(`/data/entities/roles/${nodeId}`)}
          >
            {t('Details')}
          </MenuItem>
        </Menu>
      </div>
    );
  }
}

EntitiesPartiesPopover.propTypes = {
  node: PropTypes.object,
  nodeId: PropTypes.string,
  handleOpenMenu: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(EntitiesPartiesPopover);
