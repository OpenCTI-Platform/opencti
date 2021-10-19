import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Drawer from '@material-ui/core/Drawer';
import Fab from '@material-ui/core/Fab';
import {
  Add,
  Edit,
  Close,
  Delete,
  ArrowBack,
  AddCircleOutline,
  CheckCircleOutline,
} from '@material-ui/icons';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import DeviceCreationContainer from './DeviceCreationContainer';
import DeviceCreationOverview, { deviceCreationOverviewFocus } from './DeviceCreationOverview';
import Loader from '../../../../components/Loader';
import DeviceCreationDetails from './DeviceCreationDetails';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px',
    padding: '24px',
    height: '64px',
    backgroundColor: '#1F2842',
  },
  gridContainer: {
    marginBottom: 20,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    padding: '8px 16px 8px 8px',
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  rightContainer: {
    float: 'right',
    marginTop: '-5px',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
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
});

class DeviceCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  // handleClose() {
  //   commitMutation({
  //     mutation: deviceCreationOverviewFocus,
  //     variables: {
  //       id: this.props.deviceId,
  //       input: { focusOn: '' },
  //     },
  //   });
  //   this.setState({ open: false });
  // }

  render() {
    const {
      t,
      classes,
      deviceId,
      open,
    } = this.props;
    return (
      <div className={classes.container}>
        <div className={classes.header}>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            {t('New Asset')}
          </Typography>
          <div className={classes.rightContainer}>
            <Tooltip title={t('Cancel')}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<Close />}
                color='primary'
                // onClick={this.handleCloseEdit.bind(this)}
                className={classes.iconButton}
              >
                {t('Cancel')}
              </Button>
            </Tooltip>
            <Tooltip title={t('Save')}>
              <Button
                variant="contained"
                size="small"
                startIcon={<CheckCircleOutline />}
                color='primary'
                className={classes.iconButton}
              >
                {t('Done')}
              </Button>
            </Tooltip>
          </div>
        </div>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <DeviceCreationOverview />
          </Grid>
          <Grid item={true} xs={6}>
            <DeviceCreationDetails />
          </Grid>
        </Grid>
        {/* <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={device.id}
              stixObjectOrStixRelationshipLink={`/dashboard/assets/devices/${device.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              stixCoreObjectOrStixCoreRelationshipId={device.id}
            />
          </Grid>
        </Grid> */}
        {/* <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        > */}
          {/* <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences
              stixCoreObjectId={device.id}
            />
          </Grid> */}
          {/* <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={device.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={device.id}
        /> */}
        {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <DeviceEdition deviceId={device.id} />
        </Security> */}
      </div>
    );
  }
}

DeviceCreation.propTypes = {
  deviceId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceCreation);
