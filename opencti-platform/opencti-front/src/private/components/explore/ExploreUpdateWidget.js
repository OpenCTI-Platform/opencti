import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, pipe, assoc, pathOr, map, union,
} from 'ramda';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import { stixDomainEntitiesLinesSearchQuery } from '../common/stix_domain_entities/StixDomainEntitiesLines';
import { fetchQuery } from '../../../relay/environment';
import Autocomplete from '../../../components/Autocomplete';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
});

const widgetValidation = t => Yup.object().shape({
  title: Yup.string().required(t('This field is required')),
  entity: Yup.string().required(t('This field is required')),
});

class ExploreUpdateWidget extends Component {
  constructor(props) {
    super(props);
    this.state = {
      entities: [],
      currentWidget: null,
    };
  }

  searchEntities(event) {
    fetchQuery(stixDomainEntitiesLinesSearchQuery, {
      search: event.target.value,
      count: 10,
    }).then((data) => {
      const entities = pipe(
        pathOr([], ['stixDomainEntities', 'edges']),
        map(n => ({
          label: n.node.name,
          value: n.node.id,
          type: n.node.entity_type,
        })),
      )(data);
      this.setState({ entities: union(this.state.entities, entities) });
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('id', this.props.configuration.id),
      assoc('entity', {
        id: values.entity.value,
        name: values.entity.label,
        type: values.entity.type,
      }),
    )(values);
    this.props.handleUpdate(finalValues);
    setSubmitting(false);
    resetForm();
    this.props.handleClose();
  }

  onReset() {
    this.props.handleClose();
  }

  deleteWidget() {
    this.props.handleClose();
    this.props.handleDelete(this.props.configuration.id);
  }

  render() {
    const {
      t, classes, configuration, open, handleClose,
    } = this.props;
    const initialValues = pipe(
      assoc('entity', {
        label: pathOr('', ['entity', 'name'], configuration),
        value: pathOr(null, ['entity', 'id'], configuration),
      }),
    )(configuration);
    let victimology = false;
    let distribution = false;
    let timeseries = false;
    if (this.state.currentWidget !== null) {
      victimology = this.state.currentWidget.includes('Victimology');
      distribution = this.state.currentWidget.includes('Distribution');
      timeseries = this.state.currentWidget.includes('Timeseries');
    } else if (initialValues.widget !== undefined) {
      victimology = initialValues.widget.includes('Victimology');
      distribution = initialValues.widget.includes('Distribution');
      timeseries = initialValues.widget.includes('Timeseries');
    }
    return (
      <Drawer
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose.bind(this)}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6">{t('Update a widget')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={widgetValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
            render={({ submitForm, handleReset, isSubmitting }) => (
              <div>
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    name="title"
                    component={TextField}
                    label={t('Title')}
                    fullWidth={true}
                  />
                  <Field
                    name="widget"
                    component={SelectField}
                    label={t('Widget')}
                    fullWidth={true}
                    inputProps={{
                      name: 'widget',
                      id: 'widget',
                    }}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                    onChange={(name, value) => {
                      this.setState({ currentWidget: value });
                    }}
                  >
                    <MenuItem value="VictimologyDistribution">
                      {t('[Victimology] Distribution')}
                    </MenuItem>
                    <MenuItem value="VictimologyTimeseries">
                      {t('[Victimology] Timeseries')}
                    </MenuItem>
                    <MenuItem value="CampaignsTimeseries">
                      {t('[Campaigns] Timeseries')}
                    </MenuItem>
                    <MenuItem value="IncidentsTimeseries">
                      {t('[Incidents] Timeseries')}
                    </MenuItem>
                    <MenuItem value="AttackPatternsDistribution">
                      {t('[TTPs] Distribution')}
                    </MenuItem>
                    <MenuItem value="Killchain">
                      {t('[Killchain] Tactics and procedures')}
                    </MenuItem>
                  </Field>
                  <Field
                    name="entity"
                    component={Autocomplete}
                    multiple={false}
                    label={t('Entity')}
                    options={this.state.entities}
                    onInputChange={this.searchEntities.bind(this)}
                  />
                  {victimology ? (
                    <Field
                      name="entity_type"
                      component={SelectField}
                      label={t('Entity type')}
                      fullWidth={true}
                      inputProps={{
                        name: 'entity_type',
                        id: 'entity_type',
                      }}
                      containerstyle={{ marginTop: 20, width: '100%' }}
                    >
                      <MenuItem value="Sector">{t('Sector')}</MenuItem>
                      <MenuItem value="Organization">
                        {t('Organization')}
                      </MenuItem>
                      <MenuItem value="Country">{t('Country')}</MenuItem>
                      <MenuItem value="Region">{t('Region')}</MenuItem>
                    </Field>
                  ) : (
                    ''
                  )}
                  {distribution ? (
                    <Field
                      name="graph_type"
                      component={SelectField}
                      label={t('Graph type')}
                      fullWidth={true}
                      inputProps={{
                        name: 'graph_type',
                        id: 'graph_type',
                      }}
                      containerstyle={{ marginTop: 20, width: '100%' }}
                    >
                      <MenuItem value="table">{t('Table (top 10)')}</MenuItem>
                      <MenuItem value="pie">{t('Pie chart')}</MenuItem>
                      <MenuItem value="donut">{t('Donut chart')}</MenuItem>
                      <MenuItem value="radar">{t('Radar chart')}</MenuItem>
                    </Field>
                  ) : (
                    ''
                  )}
                  {timeseries ? (
                    <Field
                      name="graph_type"
                      component={SelectField}
                      label={t('Graph type')}
                      fullWidth={true}
                      inputProps={{
                        name: 'graph_type',
                        id: 'graph_type',
                      }}
                      containerstyle={{ marginTop: 20, width: '100%' }}
                    >
                      <MenuItem value="table">{t('Table')}</MenuItem>
                      <MenuItem value="line">{t('Line chart')}</MenuItem>
                      <MenuItem value="timeline">{t('Timeline')}</MenuItem>
                    </Field>
                  ) : (
                    ''
                  )}
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
                      onClick={this.deleteWidget.bind(this)}
                      classes={{ root: classes.button }}
                    >
                      {t('Delete')}
                    </Button>
                    <Button
                      variant="contained"
                      color="primary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Update')}
                    </Button>
                  </div>
                </Form>
              </div>
            )}
          />
        </div>
      </Drawer>
    );
  }
}

ExploreUpdateWidget.propTypes = {
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleUpdate: PropTypes.func,
  handleDelete: PropTypes.func,
  configuration: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ExploreUpdateWidget);
