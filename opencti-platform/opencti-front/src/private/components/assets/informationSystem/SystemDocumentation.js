import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import AddIcon from '@material-ui/icons/Add';
import VisibilityIcon from '@material-ui/icons/Visibility';
import KeyboardArrowDownIcon from '@material-ui/icons/KeyboardArrowDown';
import {
  Button,
  Menu,
  MenuItem,
} from '@material-ui/core';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import EditIcon from '@material-ui/icons/Edit';
import inject18n from '../../../../components/i18n';
import AuthorizationBoundaryPopover from './AuthorizationBoundaryPopover';
import NetworkArchitecturePopover from './NetworkArchitecturePopover';
import DataFlowPopover from './DataFlowPopover';
import AuthorizationBoundaryEditionPopover from './AuthorizationBoundaryEditionPopover';
import NetworkArchitectureEditionPopover from './NetworkArchitectureEditionPopover';
import DataFlowEditionPopover from './DataFlowEditionPopover';
import AuthorizationBoundaryCreation from './AuthorizationBoundaryCreation';
import NetworkArchitectureCreation from './NetworkArchitectureCreation';
import DataFlowCreation from './DataFlowCreation';

const styles = (theme) => ({
  selectOptionMenu: {
    padding: '20px 10px',
    marginTop: '50px',
  },
  selectMenuItems: {
    paddingLeft: '30px',
    paddingRight: '70px',
  },
  selectIcons: {
    marginRight: '20px',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
});

class SystemDocumentationComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      openView: false,
      openEdit: false,
      openCreate: false,
      modal: '',
      mode: null,
      openInfoType: false,
    };
  }

  handleClick(event, id) {
    this.setState({
      anchorEl: event.currentTarget,
      modal: id,
    });
  }

  handleOpenView() {
    this.setState({
      anchorEl: null,
      openView: true,
      mode: 'view',
    });
  }

  handleCloseView() {
    this.setState({
      openView: false,
      modal: '',
      mode: null,
    });
  }

  handleOpenEdit() {
    this.setState({
      anchorEl: null,
      openEdit: true,
      mode: 'edit',
    });
  }

  handleOpenCreate() {
    this.setState({
      anchorEl: null,
      openCreate: true,
      mode: 'create',
    });
  }

  handleCloseEdit() {
    this.setState({
      openEdit: false,
      modal: '',
      mode: null,
    });
  }

  handleCloseCreate() {
    this.setState({
      openCreate: false,
      modal: '',
      mode: null,
    });
  }

  renderButtons(name, title) {
    const {
      t,
      classes,
      informationSystem,
    } = this.props;
    return (
      <>
        <Button
          aria-controls={
            this.state.anchorEl ? 'basic-menu' : undefined
          }
          variant='contained'
          color='primary'
          endIcon={<KeyboardArrowDownIcon />}
          style={{ marginRight: 5 }}
          onClick={(event) => this.handleClick(event, name)}
          id={name}
          aria-describedby='basic-menu'
        >
          {title && t(title)}
        </Button>
        <Menu
          id='basic-menu'
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={() => {
            this.setState({
              anchorEl: null,
            });
          }}
          MenuListProps={{
            'aria-labelledby': name,
          }}
          anchorOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
          className={classes.selectOptionMenu}
        >
          <MenuItem
            className={classes.selectMenuItems}
            onClick={this.handleOpenCreate.bind(this)}
          >
            <AddIcon className={classes.selectIcons} />
            Add
          </MenuItem>
          <MenuItem
            onClick={this.handleOpenView.bind(this)}
            className={classes.selectMenuItems}
          >
            <VisibilityIcon className={classes.selectIcons} />
            View
          </MenuItem>
          <MenuItem
            onClick={this.handleOpenEdit.bind(this)}
            className={classes.selectMenuItems}
          >
            <EditIcon className={classes.selectIcons} />
            Edit
          </MenuItem>
        </Menu>
      </>
    );
  }

  render() {
    const {
      t, classes, informationSystem,
    } = this.props;
    return (
      <>
        <Grid item={true} xs={12}>
          <div className={classes.textBase}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ margin: 0 }}
            >
              {t('System Documentation')}
            </Typography>
            <Tooltip title={t('Identifies a description of this system\'s authorization boundary, network architecture, and data flow.')}>
              <Information
                style={{ marginLeft: '5px' }}
                fontSize="inherit"
                color="disabled"
              />
            </Tooltip>
          </div>
        </Grid>
        <Grid item={true} xs={12}>
          {this.renderButtons(
            'authorization_boundary',
            'Authorization Boundary',
          )}
          {this.renderButtons(
            'network_architecture',
            'Network Architecture',
          )}
          {this.renderButtons(
            'data_flow',
            'Data Flow',
          )}
        </Grid>
        {(this.state.mode === 'view'
          && this.state.modal === 'authorization_boundary')
          && (
            <AuthorizationBoundaryPopover
              openView={this.state.openView}
              informationSystem={informationSystem}
              handleCloseView={this.handleCloseView.bind(this)}
            />
          )}
        {(this.state.mode === 'view'
          && this.state.modal === 'network_architecture')
          && (
            <NetworkArchitecturePopover
              openView={this.state.openView}
              informationSystem={informationSystem}
              handleCloseView={this.handleCloseView.bind(this)}
            />
          )}
        {(this.state.mode === 'view'
          && this.state.modal === 'data_flow')
          && (
            <DataFlowPopover
              openView={this.state.openView}
              informationSystem={informationSystem}
              handleCloseView={this.handleCloseView.bind(this)}
            />
          )}
        {(this.state.mode === 'edit'
          && this.state.modal === 'authorization_boundary')
          && (
            <AuthorizationBoundaryEditionPopover
              openEdit={this.state.openEdit}
              handleCloseEdit={this.handleCloseEdit.bind(this)}
              informationSystem={informationSystem}
            />
          )}
        {(this.state.mode === 'edit'
          && this.state.modal === 'network_architecture')
          && (
            <NetworkArchitectureEditionPopover
              openEdit={this.state.openEdit}
              handleCloseEdit={this.handleCloseEdit.bind(this)}
              informationSystem={informationSystem}
            />
          )}
        {(this.state.mode === 'edit'
          && this.state.modal === 'data_flow')
          && (
            <DataFlowEditionPopover
              openEdit={this.state.openEdit}
              handleCloseEdit={this.handleCloseEdit.bind(this)}
              informationSystem={informationSystem}
            />
          )}
        {(this.state.mode === 'create'
          && this.state.modal === 'authorization_boundary')
          && (
            <AuthorizationBoundaryCreation
              openCreate={this.state.openCreate}
              handleCloseCreate={this.handleCloseCreate.bind(this)}
            />
          )}
        {(this.state.mode === 'create'
          && this.state.modal === 'network_architecture')
          && (
            <NetworkArchitectureCreation
              openCreate={this.state.openCreate}
              handleCloseCreate={this.handleCloseCreate.bind(this)}
            />
          )}
        {(this.state.mode === 'create'
          && this.state.modal === 'data_flow')
          && (
            <DataFlowCreation
              openCreate={this.state.openCreate}
              handleCloseCreate={this.handleCloseCreate.bind(this)}
            />
          )}
      </>
    );
  }
}

SystemDocumentationComponent.propTypes = {
  informationSystem: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SystemDocumentation = createFragmentContainer(SystemDocumentationComponent, {
  informationSystem: graphql`
    fragment SystemDocumentation_information on InformationSystem {
      id
      authorization_boundary {
        id
      }
      network_architecture {
        id
      }
      data_flow {
        id
      }
      ...DataFlowPopover_information
      ...DataFlowEditionPopover_information
      ...NetworkArchitecturePopover_information
      ...AuthorizationBoundaryPopover_information
      ...NetworkArchitectureEditionPopover_information
      ...AuthorizationBoundaryEditionPopover_information
    }
  `,
});

export default compose(inject18n, withStyles(styles))(SystemDocumentation);
