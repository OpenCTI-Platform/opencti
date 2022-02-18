/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
// import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import Grid from '@material-ui/core/Grid';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import { withStyles } from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close, CheckCircleOutline } from '@material-ui/icons';
import { dateFormat, parse } from '../../../../utils/Time';
import { commitMutation } from '../../../../relay/environment';
import { QueryRenderer as QR, commitMutation as CM, createFragmentContainer } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import SoftwareEditionOverview from './SoftwareEditionOverview';
import SoftwareEditionDetails from './SoftwareEditionDetails';
import CyioDomainObjectAssetEditionOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetEditionOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import { adaptFieldValue } from '../../../../utils/String';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px -24px 20px -24px',
    padding: '14px 24px 24px 24px',
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

const softwareEditionMutation = graphql`
  mutation SoftwareEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editSoftwareAsset(id: $id, input: $input) {
      id
      # ...Software_software
      # name
      # asset_type
      # vendor_name
    }
  }
`;

const softwareValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  asset_type: Yup.string().required(t('This field is required')),
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class SoftwareEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentTab: 0,
      onSubmit: false,
      open: false,
    };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  handleOpen() {
    this.setState({ open: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = R.evolve(
      {
        release_date: () => parse(values.release_date).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      }))
    )(adaptedValues);
    CM(environmentDarkLight, {
      mutation: softwareEditionMutation,
      variables: {
        id: this.props.software.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/dashboard/assets/software');
      },
    });
    // commitMutation({
    //   mutation: softwareEditionMutation,
    //   variables: {
    //     input: values,
    //   },
    //   updater: (store) => insertNode(
    //     store,
    //     'Pagination_softwareAssetList',
    //     this.props.paginationOptions,
    //     'editSoftwareAsset',
    //   ),
    //   setSubmitting,
    //   onCompleted: (data) => {
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
      t, classes, handleClose, software,
    } = this.props;
    const { editContext } = software;
    const initialValues = R.pipe(
      R.assoc('id', software?.id || ''),
      R.assoc('asset_id', software?.asset_id || ''),
      R.assoc('description', software?.description || ''),
      R.assoc('name', software?.name || ''),
      R.assoc('asset_tag', software?.asset_tag || ''),
      R.assoc('asset_type', software?.asset_type || ''),
      R.assoc('version', software?.version || ''),
      R.assoc('vendor_name', software?.vendor_name || ''),
      R.assoc('serial_number', software?.serial_number || ''),
      R.assoc('release_date', dateFormat(software?.release_date)),
      R.assoc('operational_status', software?.operational_status || ''),
      R.assoc('software_identifier', software?.software_identifier || ''),
      R.assoc('labels', software?.labels || []),
      R.assoc('patch_level', software?.patch_level || ''),
      R.assoc('license_key', software?.license_key || ''),
      R.assoc('cpe_identifier', software?.cpe_identifier || ''),
      R.assoc('installation_id', software?.installation_id || ''),
      R.assoc('implementation_point', software?.implementation_point || ''),
      R.pick([
        'id',
        'asset_id',
        'name',
        'description',
        'asset_tag',
        'asset_type',
        'version',
        'vendor_name',
        'serial_number',
        'release_date',
        'operational_status',
        'software_identifier',
        'labels',
        'patch_level',
        'license_key',
        'cpe_identifier',
        'installation_id',
        'implementation_point',
      ]),
    )(software);
    return (
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
          validationSchema={softwareValidation(t)}
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
                    {t('EDIT: ')}
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
                    {/* <SoftwareEditionOverview
                software={software}
                // enableReferences={this.props.enableReferences}
                // context={editContext}
                handleClose={handleClose.bind(this)}
              /> */}
                    <CyioDomainObjectAssetEditionOverview
                      cyioDomainObject={software}
                      assetType="Software"
                      // enableReferences={this.props.enableReferences}
                      // context={editContext}
                      handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <SoftwareEditionDetails
                      software={software}
                      // enableReferences={this.props.enableReferences}
                      // context={editContext}
                      handleClose={handleClose.bind(this)}
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
                  <CyioCoreObjectExternalReferences
                    externalReferences={software.external_references}
                    cyioCoreObjectId={software.id}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory cyioCoreObjectId={software.id} />
                </Grid>
              </Grid>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                notes={software.notes}
                cyioCoreObjectOrCyioCoreRelationshipId={software.id}
              />
            </>
          )}
        </Formik>
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
              onClick={this.handleCancelButton.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Go Back')}
            </Button>
            <Button
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
      </div>
    );
  }
}

SoftwareEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  software: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const SoftwareEditionFragment = createFragmentContainer(
  SoftwareEditionContainer,
  {
    software: graphql`
      fragment SoftwareEditionContainer_software on SoftwareAsset {
        id
        name
        asset_id
        description
        version
        vendor_name
        asset_tag
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        external_references {
          __typename
          id
          source_name
          description
          entity_type
          url
          hashes {
            value
          }
          external_id
        }
        notes {
          id
          # created
          # modified
          entity_type
          labels {
            id
            name
            color
            description
          }
          abstract
          content
          authors
        }
        asset_type
        serial_number
        release_date
        operational_status
        software_identifier
        license_key
        cpe_identifier
        patch_level
        installation_id
        implementation_point
        # ...SoftwareEditionOverview_software
        # editContext {
        #   name
        #   focusOn
        # }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(SoftwareEditionFragment);
