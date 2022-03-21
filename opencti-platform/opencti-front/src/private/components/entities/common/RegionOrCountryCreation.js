import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { Close, FlagOutlined, LocalPlayOutlined } from '@mui/icons-material';
import { compose, pipe, pluck, assoc } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
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
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
    },
  },
});

const regionMutation = graphql`
  mutation RegionOrCountryCreationRegionMutation($input: RegionAddInput!) {
    regionAdd(input: $input) {
      id
      name
      description
      isSubRegion
      subRegions {
        edges {
          node {
            id
            name
            description
          }
        }
      }
    }
  }
`;

const countryMutation = graphql`
  mutation RegionOrCountryCreationCountryMutation($input: CountryAddInput!) {
    countryAdd(input: $input) {
      id
      name
    }
  }
`;

const regionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

const countryValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class RegionOrCountryCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, openRegion: false, openCountry: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleOpenRegion() {
    this.setState({ open: false, openRegion: true });
  }

  handleCloseRegion() {
    this.setState({ openRegion: false });
  }

  handleOpenCountry() {
    this.setState({ open: false, openCountry: true });
  }

  handleCloseCountry() {
    this.setState({ openCountry: false });
  }

  onSubmitRegion(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('createdBy', values.createdBy?.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
    )(values);
    commitMutation({
      mutation: regionMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        this.props.onCreate();
        setSubmitting(false);
        resetForm();
        this.handleCloseRegion();
      },
    });
  }

  onResetRegion() {
    this.handleCloseRegion();
  }

  onSubmitCountry(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('createdBy', values.createdBy?.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
    )(values);
    commitMutation({
      mutation: countryMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        this.props.onCreate();
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  onResetCountry() {
    this.handleCloseCountry();
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div>
        <SpeedDial
          ariaLabel="Create"
          className={classes.createButton}
          icon={<SpeedDialIcon />}
          onClose={this.handleClose.bind(this)}
          onOpen={this.handleOpen.bind(this)}
          open={this.state.open}
          FabProps={{ color: 'secondary' }}
        >
          <SpeedDialAction
            title={t('Create a region')}
            icon={<LocalPlayOutlined />}
            tooltipTitle={t('Create a region')}
            onClick={this.handleOpenRegion.bind(this)}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
          <SpeedDialAction
            title={t('Create a country')}
            icon={<FlagOutlined />}
            tooltipTitle={t('Create a country')}
            onClick={this.handleOpenCountry.bind(this)}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
        </SpeedDial>
        <Drawer
          open={this.state.openRegion}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseRegion.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleCloseRegion.bind(this)}
              size="large"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create a region')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                description: '',
                createdBy: '',
                objectMarking: [],
              }}
              validationSchema={regionValidation(t)}
              onSubmit={this.onSubmitRegion.bind(this)}
              onReset={this.onResetRegion.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    detectDuplicate={['Region']}
                  />
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <CreatedByField
                    name="createdBy"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
        <Drawer
          open={this.state.openCountry}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseCountry.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleCloseCountry.bind(this)}
              size="large"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create a country')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                description: '',
                createdBy: '',
                objectMarking: [],
              }}
              validationSchema={countryValidation(t)}
              onSubmit={this.onSubmitCountry.bind(this)}
              onReset={this.onResetCountry.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    detectDuplicate={['Country']}
                  />
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <CreatedByField
                    name="createdBy"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </div>
    );
  }
}

RegionOrCountryCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles, { withTheme: true }),
)(RegionOrCountryCreation);
