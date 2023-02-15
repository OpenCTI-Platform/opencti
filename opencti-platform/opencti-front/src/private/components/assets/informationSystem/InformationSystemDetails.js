import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import VisibilityIcon from '@material-ui/icons/Visibility';
import KeyboardArrowDownIcon from '@material-ui/icons/KeyboardArrowDown';
import {
  Button,
  Divider,
  Menu,
  MenuItem,
} from '@material-ui/core';
import EditIcon from '@material-ui/icons/Edit';
import inject18n from '../../../../components/i18n';
import AuthorizationBoundaryPopover from './AuthorizationBoundaryPopover';
import NetworkArchitecturePopover from './NetworkArchitecturePopover';
import DataFlowPopover from './DataFlowPopover';
import InformationTypeCreation from './InformationTypeCreation';
import AuthorizationBoundaryEditionPopover from './AuthorizationBoundaryEditionPopover';
import NetworkArchitectureEditionPopover from './NetworkArchitectureEditionPopover';
import DataFlowEditionPopover from './DataFlowEditionPopover';
import HyperLinkField from '../../common/form/HyperLinkField';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
});

class InformationSystemDetailsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      openView: false,
      openEdit: false,
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

  handleCloseEdit() {
    this.setState({
      openEdit: false,
      modal: '',
      mode: null,
    });
  }

  handleInformationType() {
    this.setState({ openInfoType: !this.state.openInfoType });
  }

  renderButtons(id, title) {
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
          onClick={(event) => this.handleClick(event, id)}
          id={id}
          aria-describedby='basic-menu'
        >
          {title}
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
            'aria-labelledby': id,
          }}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'center',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
          style={{ padding: '20px 10px', marginTop: '50px' }}
        >
          <MenuItem onClick={this.handleOpenView.bind(this)} style={{ paddingLeft: '30px', paddingRight: '70px' }}>
            <VisibilityIcon style={{ marginRight: '20px' }} />
            View
          </MenuItem>
          <MenuItem onClick={this.handleOpenEdit.bind(this)} style={{ paddingLeft: '30px', paddingRight: '70px' }}>
            <EditIcon style={{ marginRight: '20px' }} />
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
      <Formik
        enableReinitialize={true}
      >
        {({
          setFieldValue,
        }) => (
          <Form>
            <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Details')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={12}>
                    <HyperLinkField
                      variant='outlined'
                      type='hardware'
                      multiple={true}
                      name="installed_hardware"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '90%' }}
                      helperText={'Indicates installed hardware on this entity.'}
                      data={[]}
                      title={'Information Type(s)'}
                      setFieldValue={setFieldValue}
                      link='/defender HQ/assets/devices'
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Security Sensitivity Level')}
                      </Typography>
                      <Tooltip title={t('Security Sensitivity Level')}>
                        <Information
                          style={{ marginLeft: '5px' }}
                          fontSize="inherit"
                          color="disabled"
                        />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {/* Content here */}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Security Impact Level')}
                      </Typography>
                      <Tooltip title={t('Security Impact Level')}>
                        <Information
                          style={{ marginLeft: '5px' }}
                          fontSize="inherit"
                          color="disabled"
                        />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {/* Content here */}
                  </Grid>
                  <Grid item={true} xs={12}>
                    <Divider />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('System Implementation')}
                      </Typography>
                      <Tooltip title={t('System Implementation')}>
                        <Information
                          style={{ marginLeft: '5px' }}
                          fontSize="inherit"
                          color="disabled"
                        />
                      </Tooltip>
                    </div>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <HyperLinkField
                      variant='outlined'
                      type='hardware'
                      multiple={true}
                      name="installed_hardware"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '90%' }}
                      helperText={'Indicates installed hardware on this entity.'}
                      data={[]}
                      title={'Inventory Items'}
                      setFieldValue={setFieldValue}
                      link='/defender HQ/assets/devices'
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <HyperLinkField
                      variant='outlined'
                      type='hardware'
                      multiple={true}
                      name="installed_hardware"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '90%' }}
                      helperText={'Indicates installed hardware on this entity.'}
                      data={[]}
                      title={'Components'}
                      setFieldValue={setFieldValue}
                      link='/defender HQ/assets/devices'
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <HyperLinkField
                      variant='outlined'
                      type='hardware'
                      multiple={true}
                      name="installed_hardware"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '90%' }}
                      helperText={'Indicates installed hardware on this entity.'}
                      data={[]}
                      title={'Users'}
                      setFieldValue={setFieldValue}
                      link='/defender HQ/assets/devices'
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <HyperLinkField
                      variant='outlined'
                      type='hardware'
                      multiple={true}
                      name="installed_hardware"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '90%' }}
                      helperText={'Indicates installed hardware on this entity.'}
                      data={[]}
                      title={'Leveraged Authorization'}
                      setFieldValue={setFieldValue}
                      link='/defender HQ/assets/devices'
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <Divider />
                  </Grid>
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
                      <Tooltip title={t('System Documentation')}>
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
                      'authorizationBoundary',
                      'Authorization Boundary',
                    )}
                    {this.renderButtons(
                      'networkArchitecture',
                      'Network Architecture',
                    )}
                    {this.renderButtons('dataFlow', 'Data Flow')}
                  </Grid>
                </Grid>
              </Paper>
              <InformationTypeCreation
                openInformationType={this.state.openInfoType}
                handleInformationType={this.handleInformationType.bind(this)}
              />
              {/* View Modal */}
              {this.state.mode === 'view'
                && this.state.modal === 'authorizationBoundary' && (
                  <AuthorizationBoundaryPopover
                    openView={this.state.openView}
                    handleCloseView={this.handleCloseView.bind(this)}
                  />
              )}
              {this.state.mode === 'view'
                && this.state.modal === 'networkArchitecture' && (
                  <NetworkArchitecturePopover
                    openView={this.state.openView}
                    handleCloseView={this.handleCloseView.bind(this)}
                  />
              )}
              {this.state.mode === 'view'
                && this.state.modal === 'dataFlow' && (
                  <DataFlowPopover
                    openView={this.state.openView}
                    handleCloseView={this.handleCloseView.bind(this)}
                  />
              )}
              {/* Edit Modals */}
              {this.state.mode === 'edit'
                && this.state.modal === 'authorizationBoundary' && (
                  <AuthorizationBoundaryEditionPopover
                    openEdit={this.state.openEdit}
                    handleCloseEdit={this.handleCloseEdit.bind(this)}
                    informationSystem={informationSystem}
                  />
              )}
              {this.state.mode === 'edit'
                && this.state.modal === 'networkArchitecture' && (
                  <NetworkArchitectureEditionPopover
                    openEdit={this.state.openEdit}
                    handleCloseEdit={this.handleCloseEdit.bind(this)}
                    informationSystem={informationSystem}
                  />
              )}
              {this.state.mode === 'edit'
                && this.state.modal === 'dataFlow' && (
                  <DataFlowEditionPopover
                    openEdit={this.state.openEdit}
                    handleCloseEdit={this.handleCloseEdit.bind(this)}
                    informationSystem={informationSystem}
                  />
              )}
            </div>
          </Form>
        )}
      </Formik>
    );
  }
}

InformationSystemDetailsComponent.propTypes = {
  informationSystem: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const InformationSystemDetails = createFragmentContainer(InformationSystemDetailsComponent, {
  informationSystem: graphql`
    fragment InformationSystemDetails_information on SoftwareAsset {
      id
      software_identifier
      license_key
      cpe_identifier
      patch_level
      installation_id
      implementation_point
      last_scanned
      is_scanned
      installed_on {
        id
        entity_type
        vendor_name
        name
        version
      }
      related_risks {
        id
        name
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystemDetails);
