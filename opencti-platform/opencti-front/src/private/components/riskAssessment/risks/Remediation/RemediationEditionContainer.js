import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form, Field } from 'formik';
// import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import AppBar from '@material-ui/core/AppBar';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close, CheckCircleOutline } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM, createFragmentContainer } from 'react-relay';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../../common/stix_core_objects/StixCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import { SubscriptionAvatars } from '../../../../../components/Subscription';
import RemediationEditionGeneral from './RemediationEditionGeneral';
import RequiredAssets from './RequiredAssets';
import RelatedTasks from './RelatedTasks';
// import RiskEditionOverview from '../RiskEditionOverview';
// import RiskEditionDetails from '../RiskEditionDetails';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px -24px 30px -24px',
    padding: '15px',
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
    marginTop: -35,
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
  buttonPopover: {
    textTransform: 'capitalize',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
});

const remediationEditionMutation = graphql`
  mutation RemediationEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editComputingDeviceAsset(id: $id, input: $input) {
      name
      asset_type
      vendor_name
    }
  }
`;

const riskValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  // asset_type: Yup.array().required(t('This field is required')),
  // implementation_point: Yup.string().required(t('This field is required')),
  // operational_status: Yup.string().required(t('This field is required')),
  // first_seen: Yup.date()
  //   .nullable()
  //   .typeError(t('The value must be a date (YYYY-MM-DD)')),
  // last_seen: Yup.date()
  //   .nullable()
  //   .typeError(t('The value must be a date (YYYY-MM-DD)')),
  // sophistication: Yup.string().nullable(),
  // resource_level: Yup.string().nullable(),
  // primary_motivation: Yup.string().nullable(),
  // secondary_motivations: Yup.array().nullable(),
  // personal_motivations: Yup.array().nullable(),
  // goals: Yup.string().nullable(),
});
const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class RemediationEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    // const finalValues = pipe(
    //   assoc('createdBy', values.createdBy?.value),
    //   assoc('objectMarking', pluck('value', values.objectMarking)),
    //   assoc('objectLabel', pluck('value', values.objectLabel)),
    // )(values);
    const pair = Object.keys(values).map((key) => [{ key, value: values[key] }]);
    CM(environmentDarkLight, {
      mutation: remediationEditionMutation,
      // const adaptedValues = evolve(
      //   {
      //     published: () => parse(values.published).format(),
      //     createdBy: path(['value']),
      //     objectMarking: pluck('value'),
      //     objectLabel: pluck('value'),
      //   },
      //   values,
      // );
      variables: {
        id: this.props.risk?.id,
        input: [
          { key: 'name', value: 'Hello' },
          { key: 'asset_id', value: values.asset_id },
          { key: 'asset_tag', value: values.asset_tag },
          { key: 'description', value: values.description },
          { key: 'version', value: values.version },
          { key: 'vendor_name', value: values.vendor_name },
          { key: 'serial_number', value: values.serial_number },
          { key: 'release_date', value: values.release_date },
          { key: 'operational_status', value: values.operational_status },
        ],
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        console.log('RiskEditionDarkLightMutationData', data);
        this.props.history.push('/dashboard/risk-assessment/risks');
      },
      onError: (err) => console.log('RiskEditionDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: riskCreationOverviewMutation,
    //   variables: {
    //     input: values,
    //   },
    //   // updater: (store) => insertNode(
    //   //   store,
    //   //   'Pagination_threatActors',
    //   //   this.props.paginationOptions,
    //   //   'threatActorAdd',
    //   // ),
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
    this.setState({ onSubmit: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const {
      t, classes, handleClose, risk,
    } = this.props;
    console.log('RiskEditionPropsData', risk);
    const initialValues = R.pipe(
      R.assoc('id', risk?.id),
      R.assoc('asset_id', risk?.asset_id),
      R.assoc('description', risk?.description),
      R.assoc('name', risk?.name),
      R.assoc('asset_tag', risk?.asset_tag),
      R.assoc('asset_type', risk?.asset_type),
      R.assoc('location', risk?.locations?.map((index) => [index.description]).join('\n')),
      R.assoc('version', risk?.version),
      R.assoc('vendor_name', risk?.vendor_name),
      R.assoc('serial_number', risk?.serial_number),
      R.assoc('release_date', risk?.release_date),
      R.assoc('operational_status', risk?.operational_status),
      R.assoc('installation_id', risk?.installation_id || ''),
      R.assoc('bios_id', risk?.bios_id || ''),
      // R.assoc('connected_to_network', risk?.connected_to_network.name || ''),
      R.assoc('netbios_name', risk?.netbios_name || ''),
      R.assoc('baseline_configuration_name', risk?.baseline_configuration_name || ''),
      R.assoc('mac_address', (risk?.mac_address || []).join()),
      R.assoc('model', risk?.model || ''),
      R.assoc('hostname', risk?.hostname || ''),
      R.assoc('default_gateway', risk?.default_gateway || ''),
      R.assoc('motherboard_id', risk?.motherboard_id || ''),
      R.assoc('is_scanned', risk?.is_scanned || ''),
      R.assoc('is_virtual', risk?.is_virtual || ''),
      R.assoc('is_publicly_accessible', risk?.is_publicly_accessible || ''),
      R.assoc('uri', risk?.uri || ''),
      R.pick([
        'id',
        'asset_id',
        'name',
        'description',
        'asset_tag',
        'asset_type',
        'location',
        'version',
        'vendor_name',
        'serial_number',
        'release_date',
        'operational_status',
        'installation_id',
        'connected_to_network',
        'bios_id',
        'netbios_name',
        'baseline_configuration_name',
        'mac_address',
        'model',
        'hostname',
        'default_gateway',
        'motherboard_id',
        'is_scanned',
        'is_virtual',
        'is_publicly_accessible',
        'uri',
      ]),
    )(risk);
    // const { editContext } = risk;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
          validationSchema={riskValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <>
              <div className={classes.header}>
                <div>
                  <Typography
                    variant="h2"
                    gutterBottom={true}
                    classes={{ root: classes.title }}
                    style={{ float: 'left', marginTop: 10, marginRight: 5 }}
                  >
                    {t('Edit: ')}
                  </Typography>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="name"
                    size='small'
                    containerstyle={{ width: '50%' }}
                  />
                </div>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<Close />}
                      color='primary'
                      // onClick={() => this.props.history.goBack()}
                      onClick={this.handleOpenCancelButton.bind(this)}
                      className={classes.iconButton}
                    >
                      {t('Cancel')}
                    </Button>
                  </Tooltip>
                  <Tooltip title={t('Create')}>
                    <Button
                      variant="contained"
                      color="primary"
                      startIcon={<CheckCircleOutline />}
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.iconButton }}
                    >
                      {t('Done')}
                    </Button>
                  </Tooltip>
                </div>
              </div>
              <Form>
                <Grid
                  container={true}
                  spacing={3}
                  classes={{ container: classes.gridContainer }}
                >
                  <Grid item={true} xs={6}>
                    {/* <RiskEditionOverview
                      risk={risk}
                      enableReferences={this.props.enableReferences}
                      context={editContext}
                      handleClose={handleClose.bind(this)}
                    /> */}
                    <RemediationEditionGeneral
                      risk={risk}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    {/* <RiskEditionDetails
                      risk={risk}
                      enableReferences={this.props.enableReferences}
                      context={editContext}
                      handleClose={handleClose.bind(this)}
                    /> */}
                    <CyioCoreObjectOrCyioCoreRelationshipNotes
                      cyioCoreObjectOrCyioCoreRelationshipId={risk.id}
                    />
                  </Grid>
                </Grid>
              </Form>
              <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
                style={{ marginTop: 25 }}
              >
                <Grid item={true} xs={6}>
                  {/* <StixCoreObjectExternalReferences
                      stixCoreObjectId={remediation.id}
                    /> */}
                  {/* <CyioCoreObjectAssetCreationExternalReferences /> */}
                  <RequiredAssets />
                </Grid>
                <Grid item={true} xs={6}>
                  {/* <CyioCoreObjectLatestHistory /> */}
                  <RelatedTasks />
                </Grid>
              </Grid>
              <Dialog
                open={this.state.displayCancel}
                TransitionComponent={Transition}
                onClose={this.handleCancelButton.bind(this)}
              >
                <DialogContent>
                  <Typography style={{
                    fontSize: '18px',
                    lineHeight: '24px',
                    color: 'white',
                  }} >
                    {t('Are you sure you’d like to cancel?')}
                  </Typography>
                  <DialogContentText>
                    {t('Your progress will not be saved')}
                  </DialogContentText>
                </DialogContent>
                <DialogActions className={classes.dialogActions}>
                  <Button
                    // onClick={this.handleCloseDelete.bind(this)}
                    // disabled={this.state.deleting}
                    onClick={this.handleCancelButton.bind(this)}
                    classes={{ root: classes.buttonPopover }}
                    variant="outlined"
                    size="small"
                  >
                    {t('Go Back')}
                  </Button>
                  <Button
                    // onClick={this.submitDelete.bind(this)}
                    // disabled={this.state.deleting}
                    onClick={() => this.props.history.goBack()}
                    color="primary"
                    classes={{ root: classes.buttonPopover }}
                    variant="contained"
                    size="small"
                  >
                    {t('Yes Cancel')}
                  </Button>
                </DialogActions>
              </Dialog>
            </>
          )}
        </Formik>
      </div>
    );
  }
}

RemediationEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const RemediationEditionFragment = createFragmentContainer(
  RemediationEditionContainer,
  {
    risk: graphql`
      fragment RemediationEditionContainer_risk on ThreatActor {
        id
        # ...RiskEditionOverview_risk
        # ...RiskEditionDetails_risk
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RemediationEditionFragment);
