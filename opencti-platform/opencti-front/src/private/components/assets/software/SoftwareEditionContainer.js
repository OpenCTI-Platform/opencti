/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import { createFragmentContainer } from 'react-relay';
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
import Typography from '@material-ui/core/Typography';
import { Close } from '@material-ui/icons';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import { dateFormat, parse } from '../../../../utils/Time';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
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
    margin: '0 -1.5rem 1rem -1.5rem',
    padding: '1rem 1.5rem',
    height: '70px',
    backgroundColor: theme.palette.background.paper,
  },
  gridContainer: {
    marginBottom: 20,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    marginTop: -35,
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
      totalInitial: {},
    };
  }

  handleChangeTab(value) {
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
    
    const filteredValue = {};
    const { totalInitial } = this.state;
    const adaptedValues = R.evolve(
      {
        release_date: () => values.release_date === null ? null : parse(values.release_date).format(),
        last_scanned: () => values.last_scanned === null ? null : parse(values.last_scanned).format(),
      },
      values,
    );
    Object.keys(totalInitial).forEach((key) => {
      if (Array.isArray(adaptedValues[key])) {
        if (adaptedValues[key].some((value, i) => value !== totalInitial[key][i])) {
          filteredValue[key] = adaptedValues[key];
        }
      }
      if (!Array.isArray(adaptedValues[key]) && totalInitial[key] !== adaptedValues[key]) {
        filteredValue[key] = adaptedValues[key];
      }
    });
    const finalValues = R.pipe(
      R.dissoc('id'),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': Array.isArray(adaptFieldValue(n[1])) ? adaptFieldValue(n[1]) : [adaptFieldValue(n[1])],
      })),
    )(filteredValue);
    commitMutation({
      mutation: softwareEditionMutation,
      variables: {
        id: this.props.software.id,
        input: finalValues,
      },
      setSubmitting,
      pathname: '/defender HQ/assets/software',
      onCompleted: (data, error) => {
        if (error) {
          this.setState({ error });
        } else {
          setSubmitting(false);
          resetForm();
          this.handleClose();
          this.props.history.push('/defender HQ/assets/software');
        }
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
      t, classes, handleClose, software, refreshQuery, history
    } = this.props;
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
      R.assoc('is_scanned', software?.is_scanned),      
      R.assoc('last_scanned', software?.last_scanned),
      R.assoc('installed_on', software?.installed_on || []),
      R.assoc('related_risks', software?.related_risks || []),
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
        'is_scanned',
        'last_scanned',
        'installed_on',
        'related_risks',
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
                      startIcon={<Close />}
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
                      startIcon={<CheckCircleIcon />}
                      onClick={() => this.setState({ totalInitial: initialValues }, submitForm)}
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
                      refreshQuery={refreshQuery}
                      assetType="Software"
                      // enableReferences={this.props.enableReferences}
                      // context={editContext}
                      handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <SoftwareEditionDetails
                      software={software}
                      setFieldValue={setFieldValue}
                      values={values}
                      history={history}
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
                    refreshQuery={refreshQuery}
                    fieldName='external_references'
                    cyioCoreObjectId={software.id}
                    typename={software.__typename}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory cyioCoreObjectId={software.id} />
                </Grid>
              </Grid>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={software.__typename}
                refreshQuery={refreshQuery}
                fieldName='notes'
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
              color="secondary"
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
  refreshQuery: PropTypes.func,
  software: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const SoftwareEditionFragment = createFragmentContainer(
  SoftwareEditionContainer,
  {
    software: graphql`
      fragment SoftwareEditionContainer_software on SoftwareAsset {
        __typename
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
          __typename
          id
          # created
          # modified
          entity_type
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
        is_scanned
        last_scanned
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
