import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import AppBar from '@material-ui/core/AppBar';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import DeviceEditionOverview from './DeviceEditionOverview';
import DeviceEditionDetails from './DeviceEditionDetails';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.text.primary,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class DeviceEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const {
      t, classes, handleClose, device,
    } = this.props;
    console.log('DeviceEditionPropsData', this.props);
    const { editContext } = device;
    return (
      <div>
        {/* <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a device')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div> */}
        <div className={classes.container}>
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={6}>
              <DeviceEditionOverview
                device={device}
                // enableReferences={this.props.enableReferences}
                // context={editContext}
                handleClose={handleClose.bind(this)}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <DeviceEditionDetails
                device={this.props.device}
                // enableReferences={this.props.enableReferences}
                context={editContext}
                handleClose={handleClose.bind(this)}
              />
            </Grid>
          </Grid>
          {/* <AppBar position="static" elevation={0} className={classes.appBar}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}
            >
              <Tab label={t('Overview')} />
              <Tab label={t('Details')} />
            </Tabs>
          </AppBar>
          {this.state.currentTab === 0 && (
            <DeviceEditionOverview
              device={this.props.device}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
          {this.state.currentTab === 1 && (
            <DeviceEditionDetails
              device={this.props.device}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )} */}
        </div>
      </div>
    );
  }
}

DeviceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  device: PropTypes.object,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const DeviceEditionFragment = createFragmentContainer(
  DeviceEditionContainer,
  {
    device: graphql`
      fragment DeviceEditionContainer_device on ThreatActor {
        id
        ...DeviceEditionOverview_device
        ...DeviceEditionDetails_device
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceEditionFragment);
