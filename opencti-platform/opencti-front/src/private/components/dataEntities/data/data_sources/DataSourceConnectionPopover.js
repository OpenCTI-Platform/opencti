/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import SwitchField from '../../../../../components/SwitchField';
import SelectField from '../../../../../components/SelectField';
import AddressField from '../../../common/form/AddressField';
import { httpHeaderRegex, CertificateRegex } from '../../../../../utils/Network';
import { Switch } from '@material-ui/core';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.background.paper,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'auto',
    overflowX: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
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
  thumb: {
    '&.MuiSwitch-thumb': {
      color: 'white',
    },
  },
  switch_track: {
    backgroundColor: '#D3134A !important',
    opacity: '1 !important',
  },
  switch_base: {
    color: 'white',
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC !important',
      opacity: 1,
    },
  },
  queryFieldContainer: {
      overflowX: 'auto',
      whiteSpace: 'nowrap',
      '&::-webkit-scrollbar': {
        width: '2em',
        height: '0.5em',
      },
      '&::-webkit-scrollbar-track': {
        '-webkit-box-shadow': 'inset 0 0 6px rgba(0,0,0,0.00)',
      },

      '&::-webkit-scrollbar-track-piece:end': {
        marginRight: '350px', 
      },  
  }
});

export class DataSourceConnectionPopoverComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      close: false,
    };
  }

  handleCancelOpenClick() {
    this.setState({ close: true });
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  handleCloseMain() {
    this.setState({ close: false });
    this.props.handleCloseConnection();
  }

  render() {
    const {
      t,
      classes,
      dataSource,
    } = this.props;
    const { connection_information } = dataSource;
    return (
      <>
        <Dialog open={this.props.openConnection} keepMounted={true}>
          <DialogTitle classes={{ root: classes.dialogTitle }}>
            {t("Connection")}
          </DialogTitle>
          <DialogContent classes={{ root: classes.dialogContent }}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                <div style={{ marginBottom: "10px" }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: "left" }}
                  >
                    {t("Name")}
                  </Typography>
                  <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                    <Tooltip title={t("Name")}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {connection_information?.name && t(connection_information?.name)}
                </div>
              </Grid>
              <Grid item={true} xs={12}>
                <div className={classes.textBase}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ margin: 0 }}
                  >
                    {t("Description")}
                  </Typography>
                  <Tooltip title={t("Description")}>
                    <Information
                      style={{ marginLeft: "5px" }}
                      fontSize="inherit"
                      color="disabled"
                    />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.description &&
                    t(connection_information.description)}
              </Grid>
              <Grid item={true} xs={6}>
                <div className={classes.textBase}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ margin: 0 }}
                  >
                    {t("Secure Connection")}
                  </Typography>
                  <Tooltip title={t("Secure Connection")}>
                    <Information
                      style={{ marginLeft: "5px" }}
                      fontSize="inherit"
                      color="disabled"
                    />
                  </Tooltip>
                  <Switch
                  disabled
                  defaultChecked={connection_information?.secure}
                  classes={{
                    thumb: classes.thumb,
                    track: classes.switch_track,
                    switchBase: classes.switch_base,
                    colorPrimary: classes.switch_primary,
                  }}
                />
                </div>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Connector Type")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Connector Type")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.connector_type && t(connection_information?.connector_type)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Host/IP")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Host/IP")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.host && t(connection_information?.host)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Port")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Port")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.port && t(connection_information.port)}
              </Grid>
              <Grid item={true} xs={12}>
                <div className={classes.queryFieldContainer}>
                  <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("Query")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Query")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {connection_information?.query && t(connection_information.query)}
                </div>                
              </Grid>
              <Grid item={true} xs={12}>
                <div className={classes.queryFieldContainer}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: "left" }}
                  >
                    {t("Initial Query")}
                  </Typography>
                  <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                    <Tooltip title={t("Initial Query")}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {connection_information?.query_initial && t(connection_information.query_initial)}
                </div>                
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Query Index Field")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Query Index Field")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.query_index_field && t(connection_information?.query_index_field)}                
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Query Sleep Interval")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Query Sleep Interval")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.query_sleep_interval && t(connection_information.query_sleep_interval)}
              </Grid>
              <Grid item xs={12}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("CA")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Indicates the file(s) containing the Certificate Authority for the connection. The value must be a file path that includes the name of the file.")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {Array.isArray(connection_information.ca) && connection_information?.ca.length > 0 && connection_information.ca.map((item) => (
                    <>{item}</>
                ))}
              </Grid>
              <Grid item xs={12}>
              <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Headers")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("Indicates the set of headers to be used.")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {Array.isArray(connection_information?.headers) && connection_information?.headers.length > 0 && connection_information.headers.map((item) => (
                    <>{item}</>
                ))}
              </Grid>
              <Grid item={true} xs={12}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("API Key")}
                </Typography>
                <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                  <Tooltip title={t("API Key")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.api_key && t(connection_information.api_key)}
              </Grid>
            </Grid>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Username")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Username")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.username && t(connection_information?.username)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Passphrase")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Passphrase")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.passphrase && t(connection_information?.passphrase)}
              </Grid>
            </Grid>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Listen Queue")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Listen Queue")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.listen && t(connection_information?.listen)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Listen Exchange")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Listen Exchange")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.listen_exchange && t(connection_information?.listen_exchange)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Post Queue")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Post Queue")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.post_queue && t(connection_information?.post_queue)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Post Exchange")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Post Exchange")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {connection_information?.post_queue && t(connection_information?.post_queue)}
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions classes={{ root: classes.dialogClosebutton }}>
            <Button
              variant="outlined"
              onClick={this.handleCloseMain.bind(this)}
              classes={{ root: classes.buttonPopover }}
            >
              {t("Cancel")}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

DataSourceConnectionPopoverComponent.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  dataSource: PropTypes.object,
  openConnection: PropTypes.bool,
  handleCloseConnection: PropTypes.func,
};


const DataSourceConnectionPopover = createFragmentContainer(
  DataSourceConnectionPopoverComponent,
  {
    dataSource: graphql`
      fragment DataSourceConnectionPopover_data on DataSource {
        connection_information {
          id
          entity_type
          created
          modified
          name
          description
          secure
          host
          port
          query
          query_initial
          query_index_field
          query_sleep_interval
          ca
          api_key
          username
          passphrase
          listen
          listen_exchange
          push
          push_exchange
          connector_type
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DataSourceConnectionPopover);
