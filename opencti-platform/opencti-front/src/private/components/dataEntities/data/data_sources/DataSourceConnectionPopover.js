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
import Switch from '@material-ui/core/Switch';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import SwitchField from '../../../../../components/SwitchField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
import { toastGenericError } from "../../../../../utils/bakedToast";
import AddressField from '../../../common/form/AddressField';

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
    overflow: 'hidden',
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
    const connectionInformation = dataSource.connection_information;
    const initialValues = R.pipe(
      R.assoc('name', connectionInformation?.name || ''),
      R.assoc('description', connectionInformation?.description || ''),
      R.assoc('secure', connectionInformation?.secure || ''),
      R.assoc('host', connectionInformation?.host || ''),
      R.assoc('port', connectionInformation?.port || ''),
      R.assoc('query', connectionInformation?.query || ''),
      R.assoc('ca', connectionInformation?.ca || ''),
      R.assoc('query_initial', connectionInformation?.query_initial || ''),
      R.assoc('query_index_field', connectionInformation?.query_index_field || ''),
      R.assoc('passphrase', connectionInformation?.passphrase || ''),
      R.assoc('listen', connectionInformation?.listen || ''),
      R.assoc('listen_exchange', connectionInformation?.listen_exchange || ''),
      R.assoc('headers', connectionInformation?.headers || ''),
      R.assoc('push', connectionInformation?.push || ''),
      R.assoc('push_exchange', connectionInformation?.push_exchange || ''),
      R.assoc('query_sleep_interval', connectionInformation?.query_sleep_interval || ''),
      R.assoc('api_key', connectionInformation?.api_key || ''),
      R.assoc('username', connectionInformation?.username || ''),
      R.pick([
        'name',
        'description',
        'secure',
        'host',
        'ca',
        'headers',
        'port',
        'query',
        'query_initial',
        'api_key',
        'username',
        'query_index_field',
        'passphrase',
        'listen',
        'listen_exchange',
        'push',
        'push_exchange',
        'query_sleep_interval',
      ]),
    )(connectionInformation);
    return (
      <>
        <Dialog
          open={this.props.openConnection}
          keepMounted={true}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
          // onSubmit={this.onSubmit.bind(this)}
          // onReset={this.onReset.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t('Connection')}
                </DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="name"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={12}>
                      <div className={classes.textBase}>
                        <Typography variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Description')}
                        </Typography>
                        <Tooltip title={t('Description')}>
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Secure Connection')}
                        </Typography>
                        <Tooltip title={t('Secure Connection')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                        <Typography style={{ marginLeft: 20 }}>No</Typography>
                        <Field
                          component={SwitchField}
                          type="checkbox"
                          name="secure"
                          containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
                          inputProps={{ 'aria-label': 'ant design' }}
                        />
                        <Typography>Yes</Typography>
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Host/IP')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Host/IP')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="host"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Port')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Port')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="port"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Query')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Query')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="query"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Initial Query')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Initial Query')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="query_initial"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Query Index Field')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Query Index Field')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="query_index_field"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Query Sleep Interval')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Query Sleep Interval')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="query_sleep_interval"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <AddressField
                        setFieldValue={setFieldValue}
                        values={values}
                        addressValues={values.ca}
                        title='CA'
                        name='ca'
                      // validation={macAddrRegex}
                      // helperText='Please enter a valid MAC Address. Example: 78:B0:92:0D:EF:1C'
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <AddressField
                        setFieldValue={setFieldValue}
                        values={values}
                        addressValues={values.headers}
                        title='Headers'
                        name='headers'
                      // validation={macAddrRegex}
                      // helperText='Please enter a valid MAC Address. Example: 78:B0:92:0D:EF:1C'
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('API Key')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('API Key')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="api_key"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Username')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Username')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="username"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Passphrase')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Passphrase')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="passphrase"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Listen Queue')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Listen Queue')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="listen"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Listen Exchange')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Listen Exchange')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="listen_exchange"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Post Queue')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Post Queue')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="post_queue"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Post Exchange')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Post Exchange')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="post_queue"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    // onClick={handleReset}
                    onClick={this.handleCancelOpenClick.bind(this)}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Submit')}
                  </Button>
                </DialogActions>

                <Dialog
                  open={this.state.close}
                  keepMounted={true}
                >
                  <DialogContent>
                    <Typography className={classes.popoverDialog}>
                      {t('Are you sure you’d like to cancel?')}
                    </Typography>
                    <Typography align='left'>
                      {t('Your progress will not be saved')}
                    </Typography>
                  </DialogContent>
                  <DialogActions className={classes.dialogActions}>
                    <Button
                      onClick={this.handleCancelCloseClick.bind(this)}
                      classes={{ root: classes.buttonPopover }}
                      variant='outlined'
                      size='small'
                    >
                      {t('Go Back')}
                    </Button>
                    <Button
                      onClick={this.handleCloseMain.bind(this)}
                      color='secondary'
                      classes={{ root: classes.buttonPopover }}
                      variant='contained'
                      size='small'
                    >
                      {t('Yes, Cancel')}
                    </Button>
                  </DialogActions>
                </Dialog>
              </Form>
            )}
          </Formik>
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
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DataSourceConnectionPopover);
