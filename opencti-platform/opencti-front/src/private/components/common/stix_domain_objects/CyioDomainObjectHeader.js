/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Slide from '@material-ui/core/Slide';
import {
  Add,
  Close,
  Delete,
  Edit,
  ArrowBack,
  AddCircleOutline,
} from '@material-ui/icons';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  header: {
    margin: '0 -1.5rem 1rem -1.5rem',
    padding: '1.5rem',
    height: '70px',
    backgroundColor: theme.palette.background.paper,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    padding: '7px',
  },
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  aliases: {
    display: 'flex',
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
      name,
      goBack,
      classes,
      history,
      disabled,
      disablePopover,
      cyioDomainObject,
      handleDisplayEdit,
      OperationsComponent,
      handleOpenNewCreation,
    } = this.props;
    return (
      <div className={classes.header}>
        <Tooltip title={t('Back')} style={{ marginTop: -5 }}>
          <Button variant="outlined" className={classes.iconButton} size="large" onClick={() => history.push(goBack)}>
            <ArrowBack fontSize="inherit" />
          </Button>
        </Tooltip>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {name}
        </Typography>
        <div className={classes.aliases}>
          {/* <Security needs={[KNOWLEDGE_KNUPDATE]}> */}
          {handleDisplayEdit && <Tooltip title={t('Edit')}>
            <Button
              variant="contained"
              onClick={handleDisplayEdit?.bind(this)}
              className={classes.iconButton}
              disabled={Boolean(!cyioDomainObject?.id) || disabled}
              color="primary"
              size="large"
            >
              <Edit fontSize="inherit" />
            </Button>
          </Tooltip>}
          <div style={{ display: 'inline-block' }}>
            {OperationsComponent && React.cloneElement(OperationsComponent, {
              id: [cyioDomainObject?.id],
              disabled: disablePopover,
            })}
          </div>
          <Tooltip title={t('Create New')}>
            <Button
              variant="contained"
              size="small"
              onClick={handleOpenNewCreation && handleOpenNewCreation.bind(this)}
              startIcon={<AddCircleOutline />}
              disabled={disabled || !handleOpenNewCreation || false}
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
  name: PropTypes.string,
  variant: PropTypes.string,
  classes: PropTypes.object,
  goBack: PropTypes.string,
  t: PropTypes.func,
  disabled: PropTypes.bool,
  fld: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
  disablePopover: PropTypes.bool,
  isOpenctiAlias: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(CyioDomainObjectAssetHeader);
