import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import {
  compose, propOr, filter, append, take,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import Slide from '@material-ui/core/Slide';
import {
  Add,
  Close,
  Delete,
  Edit,
  ArrowBack,
  AddCircleOutline,
} from '@material-ui/icons';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Dialog from '@material-ui/core/Dialog';
import Tooltip from '@material-ui/core/Tooltip';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItemText from '@material-ui/core/ListItemText';
import { DialogTitle } from '@material-ui/core';
import InputLabel from '@material-ui/core/InputLabel/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import Select from '@material-ui/core/Select/Select';
import MenuItem from '@material-ui/core/MenuItem';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  header: {
    margin: '-25px -24px 20px -24px',
    padding: '24px',
    height: '64px',
    backgroundColor: '#1F2842',
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    padding: '7px',
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  aliases: {
    float: 'right',
    marginTop: '-5px',
  },
  alias: {
    marginRight: 7,
  },
  aliasesInput: {
    margin: '4px 15px 0 10px',
    float: 'right',
  },
  viewAsField: {
    marginTop: -5,
    float: 'left',
  },
  viewAsFieldLabel: {
    margin: '5px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
});

class CyioDomainObjectAssetHeader extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openAlias: false,
      openAliases: false,
      openAliasesCreate: false,
    };
  }

  render() {
    const {
      t,
      classes,
      cyioDomainObject,
      handleDisplayEdit,
      OperationsComponent,
      handleOpenNewCreation,
      disablePopover,
    } = this.props;
    return (
      <div className={classes.header}>
        <Tooltip title={t('Back')} style={{ marginTop: -5 }}>
          <Button variant="outlined" className={classes.iconButton} size="large" onClick={() => this.props.history.goBack()}>
            <ArrowBack fontSize="inherit" />
          </Button>
        </Tooltip>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {cyioDomainObject.name && cyioDomainObject.name}
        </Typography>
        <div className={classes.aliases}>
          {/* <Security needs={[KNOWLEDGE_KNUPDATE]}> */}
            <Tooltip title={t('Edit')}>
              <Button
                variant="contained"
                onClick={handleDisplayEdit.bind(this)}
                className={classes.iconButton}
                disabled={Boolean(!cyioDomainObject.id)}
                color="primary"
                size="large"
              >
                <Edit fontSize="inherit" />
              </Button>
            </Tooltip>
            <div style={{ display: 'inline-block' }}>
              {OperationsComponent && React.cloneElement(OperationsComponent, {
                id: cyioDomainObject.id,
                disabled: disablePopover,
              })}
            </div>
            <Tooltip title={t('Create New')}>
              <Button
                variant="contained"
                size="small"
                onClick={handleOpenNewCreation && handleOpenNewCreation.bind(this)}
                startIcon={<AddCircleOutline />}
                style={{ marginTop: '-23px' }}
                color='primary'
              >
                {t('New')}
              </Button>
            </Tooltip>
          {/* </Security> */}
        </div>
      </div>
    );
  }
}

CyioDomainObjectAssetHeader.propTypes = {
  cyioDomainObject: PropTypes.object,
  PopoverComponent: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
  disablePopover: PropTypes.bool,
  isOpenctiAlias: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(CyioDomainObjectAssetHeader);
