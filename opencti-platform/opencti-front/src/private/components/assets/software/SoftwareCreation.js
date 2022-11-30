/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose, evolve } from 'ramda';
import { Formik, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import { Close, CheckCircleOutline } from '@material-ui/icons';
import { parse } from '../../../../utils/Time';
import Search from '@material-ui/icons/Search';
import Dialog from '@material-ui/core/Dialog';
import Autocomplete from '@material-ui/lab/Autocomplete';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import TextField from '@material-ui/core/TextField';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetCreationOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetCreationOverview';
import SoftwareCreationDetails from './SoftwareCreationDetails';
import CyioCoreObjectAssetCreationExternalReferences from '../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import { toastGenericError } from "../../../../utils/bakedToast";

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '0 -1.5rem 1rem -1.5rem',
    padding: '1rem 1.5rem',
    height: '70px',
    backgroundColor: theme.palette.background.paper,
    display: 'flex',
    justifyContent: 'space-between',
  },
  gridContainer: {
    marginBottom: 20,
  },
  iconButton: {
    minWidth: '0px',
    marginRight: 15,
    padding: '8px 16px 8px 8px',
  },
  title: {
    float: 'left',
  },
  rightContainer: {
    display: 'flex',
    alignItems: 'center',
  },
  leftContainer: {
    display: 'flex',
    alignItems: 'center',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  autocomplete: {
    width: '450px',
    marginLeft: '10px',
    '&.MuiAutocomplete-endAdornment, &.MuiAutocomplete-popupIndicatorOpen': {
      transform: 'none !important',
    },
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popupIndicator: {
    transform: 'none',
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

const softwareCreationMutation = graphql`
  mutation SoftwareCreationMutation($input: SoftwareAssetAddInput) {
    createSoftwareAsset (input: $input) {
      id
      # ...SoftwareCard_node
      # operational_status
      # serial_number
      # release_date
      # description
      # version
      # name
    }
  }
`;

const softwareCreationProductQuery = graphql`
  query SoftwareCreationProductQuery($search: String, $filters: [ProductFiltering], $orderedBy: ProductOrdering, $orderMode: OrderingMode) {
    products(search: $search, filters: $filters, orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const softwareCreationProductIdQuery = graphql`
  query SoftwareCreationProductIdQuery( $id: ID!) {
    product(id: $id) {
      id
      created
      modified
      name
      vendor
      version
      cpe_identifier
      ... on SoftwareProduct {
        software_identifier
      }
    }
  }
`;

const softwareValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class SoftwareCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      openAutocomplete: false,
      products: [],
      productName: '',
      onSubmit: false,
      selectedProduct: {},
      displayCancel: false,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  searchProducts(event, value) {
    this.setState({ productName: value });
    if (event.type === 'click' && value) {
      const selectedProductValue = this.state.products.filter((product) => product.label === value)[0];
      fetchQuery(softwareCreationProductIdQuery, {
        id: selectedProductValue.value,
      }).toPromise()
        .then((data) => {
          this.setState({ selectedProduct: data.product });
        })
    }
  }

  handleSearchProducts() {
    this.setState({ selectedProduct: { name: this.state.productName }, openAutocomplete: true });
    (this.state.productName.length > 2) && fetchQuery(softwareCreationProductQuery, {
      search: this.state.productName,
      orderedBy: 'name',
      orderMode: 'asc',
      filters: [
        { key: 'object_type', values: ['software'] }
      ],
    })
      .toPromise()
      .then((data) => {
        const products = R.pipe(
          R.pathOr([], ['products', 'edges']),
          R.map((n) => ({
            label: n.node.name,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          products: R.union(this.state.products, products),
        });
      })
      .catch((err) => {
        const ErrorResponse = err.res.errors;
        this.setState({ error: ErrorResponse });
      });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = evolve(
      {
        release_date: () => values.release_date === null ? null : parse(values.release_date).format(),
        last_scanned: () => values.last_scanned === null ? null : parse(values.last_scanned).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.assoc('asset_type', values.asset_type),
      R.dissoc('labels'),
    )(adaptedValues);
    commitMutation({
      mutation: softwareCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      pathname: '/defender HQ/assets/software',
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/defender HQ/assets/software');
      },
      onError: () => {
        toastGenericError('Failed to create Software');
      }
    });
    // commitMutation({
    //   mutation: softwareCreationMutation,
    //   variables: {
    //     input: values,
    //   },
    //   updater: (store) => insertNode(
    //     store,
    //     'Pagination_softwareAssetList',
    //     this.props.paginationOptions,
    //     'createSoftwareAsset',
    //   ),
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

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { t, classes } = this.props;
    const {
      selectedProduct
    } = this.state;
    return (
      <div className={classes.container}>
        <Formik
          enableReinitialize
          initialValues={{
            name: selectedProduct?.name || '',
            asset_id: '',
            version: selectedProduct?.version || '',
            serial_number: '',
            asset_tag: '',
            vendor_name: selectedProduct.vendor || '',
            release_date: null,
            software_identifier: selectedProduct?.software_identifier || '',
            license_key: '',
            installation_id: '',
            patch_level: '',
            cpe_identifier: selectedProduct?.cpe_identifier || '',
            description: '',
            operational_status: 'other',
            implementation_point: 'external',
            labels: [],
            asset_type: 'software',
            is_scanned: false,
            last_scanned: null,
          }}
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
                <div className={classes.leftContainer}>
                  <Typography
                    variant="h4"
                    gutterBottom={true}
                    classes={{ root: classes.title }}
                  >
                    {t('EDIT: ')}
                  </Typography>
                  <Autocomplete
                    open={this.state.openAutocomplete}
                    onClose={() => this.setState({ openAutocomplete: false })}
                    size="small"
                    loading={selectedProduct.name || false}
                    loadingText='Searching...'
                    className={classes.autocomplete}
                    classes={{
                      popupIndicatorOpen: classes.popupIndicator,
                    }}
                    noOptionsText={t('No available options')}
                    popupIcon={<Search onClick={this.handleSearchProducts.bind(this)} />}
                    options={this.state.products}
                    getOptionLabel={(option) => option.label ? option.label : option}
                    onInputChange={this.searchProducts.bind(this)}
                    selectOnFocus={true}
                    autoHighlight={true}
                    renderInput={(params) => (
                      <TextField
                        variant='outlined'
                        {...params}
                        inputProps={{
                          ...params.inputProps,
                          onKeyDown: (e) => {
                            if (e.key === 'Enter') {
                              e.stopPropagation();
                              this.handleSearchProducts()
                            }
                          },
                        }}
                        label='Products'
                      />
                    )}
                  />
                </div>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<Close />}
                      color='primary'
                      // onClick={handleReset}
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
                    <CyioDomainObjectAssetCreationOverview
                      setFieldValue={setFieldValue}
                      values={values}
                      assetType="Software"
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <SoftwareCreationDetails setFieldValue={setFieldValue} />
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
                      stixCoreObjectId={software.id}
                    /> */}
                  <div>
                    <CyioCoreObjectAssetCreationExternalReferences disableAdd={true} />
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory />
                </Grid>
              </Grid>
              <div>
                <CyioCoreObjectOrCyioCoreRelationshipNotes height='100px' disableAdd={true} />
              </div>
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
              onClick={() => this.props.history.push('/defender HQ/assets/software')}
              // onClick={() => history.goBack()}
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

SoftwareCreation.propTypes = {
  softwareId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(SoftwareCreation);
