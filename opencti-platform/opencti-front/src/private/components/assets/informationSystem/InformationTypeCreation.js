/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import DialogContent from '@material-ui/core/DialogContent';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import Autocomplete from '@material-ui/lab/Autocomplete';
import Search from '@material-ui/icons/Search';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { toastGenericError } from '../../../../utils/bakedToast';

const styles = (theme) => ({
  dialogMain: {
    overflowY: 'scroll',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflow: 'hidden',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
});

const informationTypeCreationQuery = graphql`
  query InformationTypeCreationQuery($search: String, $filters: [ProductFiltering], $orderedBy: ProductOrdering, $orderMode: OrderingMode) {
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

const informationTypeCreationIdQuery = graphql`
  query InformationTypeCreationIdQuery( $id: ID!) {
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

const informationTypeCreationMutation = graphql`
  mutation InformationTypeCreationMutation($input: OscalRoleAddInput) {
    createOscalRole (input: $input) {
      id
    }
  }
`;
const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class InformationTypeCreation extends Component {
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

  searchProducts(event, value) {
    this.setState({ productName: value });
    if (event.type === 'click' && value) {
      const selectedProductValue = this.state.products.filter(
        (product) => product.label === value,
      )[0];
      fetchQuery(informationTypeCreationIdQuery, {
        id: selectedProductValue.value,
      }).toPromise()
        .then((data) => {
          this.setState({ selectedProduct: data.product });
        });
    }
  }

  handleSearchProducts() {
    this.setState({ selectedProduct: { name: this.state.productName }, openAutocomplete: true });
    (this.state.productName.length > 2) && fetchQuery(informationTypeCreationQuery, {
      search: this.state.productName,
      orderedBy: 'name',
      orderMode: 'asc',
      filters: [
        { key: 'object_type', values: ['software'] },
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
    const finalValues = R.pipe(
      R.assoc('name', values.name),
      R.dissoc('created'),
      R.dissoc('modified'),
    )(values);
    commitMutation({
      mutation: informationTypeCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      pathname: '/defender HQ/assets/information_systems',
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.props.history.push('/defender HQ/assets/information_systems');
      },
      onError: () => {
        toastGenericError('Failed to create responsibility');
      },
    });
  }

  onReset() {
    this.props.handleInformationType('');
  }

  render() {
    const {
      t,
      classes,
      openInformationType,
    } = this.props;
    const {
      selectedProduct,
    } = this.state;
    return (
      <>
        <Dialog
          open={openInformationType}
          keepMounted={true}
          maxWidth='md'
          className={classes.dialogMain}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              name: selectedProduct?.name || '',
              created: null,
              modified: null,
              short_name: '',
              role_identifier: '',
              description: '',
            }}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({
              handleReset,
              submitForm,
              isSubmitting,
              setFieldValue,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Graph')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Name')}
                        </Typography>
                        <Tooltip title={t('Name')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
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
                        getOptionLabel={(option) => (option.label ? option.label : option)}
                        onInputChange={this.searchProducts.bind(this)}
                        selectOnFocus={true}
                        autoHighlight={true}
                        renderInput={(params) => (
                          // <TextField
                          //   variant='outlined'
                          //   {...params}
                          //   inputProps={{
                          //     ...params.inputProps,
                          //     onKeyDown: (e) => {
                          //       if (e.key === 'Enter') {
                          //         e.stopPropagation();
                          //         this.handleSearchProducts()
                          //       }
                          //     },
                          //   }}
                          //   label='Products'
                          // />
                          <Field
                            component={TextField}
                            name="name"
                            fullWidth={true}
                            size="small"
                            containerstyle={{ width: "100%" }}
                            variant="outlined"
                          />
                        )}
                      />
                    </Grid>
                    <Grid xs={12} item={true}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
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
                        name='description'
                        fullWidth={true}
                        multiline={true}
                        rows='2'
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Categorization System')}
                        </Typography>
                        <Tooltip title={t('Categorization System')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="categorization_system"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Category')}
                        </Typography>
                        <Tooltip title={t('Category')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="category"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Information Type')}
                        </Typography>
                        <Tooltip title={t('Information Type')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="information_type"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div
                        className={classes.textBase}
                      >
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Confidentiality Impact')}
                        </Typography>
                        <Tooltip title={t('Confidentiality Impact')} >
                          <Information style={{ marginLeft: '5px' }}
                            fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                    </Grid>
                    <Grid item={true} xs={2}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Base')}
                        </Typography>
                        <Tooltip title={t('Base')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="information_type"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={2}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Selected')}
                        </Typography>
                        <Tooltip title={t('Selected')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="selected"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid xs={8} item={true}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Justification')}
                        </Typography>
                        <Tooltip title={t('Justification')}>
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name='justification'
                        fullWidth={true}
                        multiline={true}
                        rows='2'
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div
                        className={classes.textBase}
                      >
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Integrity Impact')}
                        </Typography>
                        <Tooltip title={t('Integrity Impact')} >
                          <Information style={{ marginLeft: '5px' }}
                            fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                    </Grid>
                    <Grid item={true} xs={2}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Base')}
                        </Typography>
                        <Tooltip title={t('Base')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="information_type"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={2}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Selected')}
                        </Typography>
                        <Tooltip title={t('Selected')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="selected"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid xs={8} item={true}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Justification')}
                        </Typography>
                        <Tooltip title={t('Justification')}>
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name='justification'
                        fullWidth={true}
                        multiline={true}
                        rows='2'
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div
                        className={classes.textBase}
                      >
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Availability Impact')}
                        </Typography>
                        <Tooltip title={t('Availability Impact')} >
                          <Information style={{ marginLeft: '5px' }}
                            fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                    </Grid>
                    <Grid item={true} xs={2}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Base')}
                        </Typography>
                        <Tooltip title={t('Base')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="information_type"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={2}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Selected')}
                        </Typography>
                        <Tooltip title={t('Selected')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="selected"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid xs={8} item={true}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Justification')}
                        </Typography>
                        <Tooltip title={t('Justification')}>
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name='justification'
                        fullWidth={true}
                        multiline={true}
                        rows='2'
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    onClick={handleReset}
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
              </Form>
            )}
          </Formik>
        </Dialog>
      </>
    );
  }
}

InformationTypeCreation.propTypes = {
  openInformationType: PropTypes.bool,
  handleInformationType: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(InformationTypeCreation);
