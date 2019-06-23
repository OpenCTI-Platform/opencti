import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import uuid from 'uuid/v4';
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
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import * as Yup from 'yup';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import Select from '../../../components/Select';
import { stixDomainEntitiesLinesSearchQuery } from '../stix_domain_entity/StixDomainEntitiesLines';
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
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
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

class ExploreAddWidget extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      entities: [],
      currentWidget: '',
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  searchEntities(event) {
    fetchQuery(stixDomainEntitiesLinesSearchQuery, {
      search: event.target.value,
      count: 10,
    }).then((data) => {
      const entities = pipe(
        pathOr([], ['stixDomainEntities', 'edges']),
        map(n => ({ label: n.node.name, value: n.node.id })),
      )(data);
      this.setState({ entities: union(this.state.entities, entities) });
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('id', uuid()),
      assoc('entity', { id: values.entity.value, name: values.entity.label }),
    )(values);
    this.props.onAdd(finalValues);
    setSubmitting(false);
    resetForm();
    this.handleClose();
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6">{t('Add a widget')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                title: '',
                entity: '',
                widget: '',
              }}
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
                      component={Select}
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
                        {t('Victimology distribution')}
                      </MenuItem>
                      <MenuItem value="VictimologyTimeseries">
                        {t('Victimology timeseries')}
                      </MenuItem>
                      <MenuItem value="CampaignsTimeseries">
                        {t('Campaigns timeseries')}
                      </MenuItem>
                      <MenuItem value="Killchains">
                        {t('Killchains')}
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
                    {this.state.currentWidget.includes('Victimology') ? (
                      <Field
                        name="entity_type"
                        component={Select}
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
                    {this.state.currentWidget.includes('Distribution') ? (
                      <Field
                        name="graph_type"
                        component={Select}
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
                    {this.state.currentWidget.includes('Timeseries') ? (
                      <Field
                        name="graph_type"
                        component={Select}
                        label={t('Graph type')}
                        fullWidth={true}
                        inputProps={{
                          name: 'graph_type',
                          id: 'graph_type',
                        }}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                      >
                        <MenuItem value="table">{t('Table')}</MenuItem>
                        <MenuItem value="chart">{t('Lines chart')}</MenuItem>
                        <MenuItem value="timeline">{t('Timeline chart')}</MenuItem>
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
                        color="primary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Add')}
                      </Button>
                    </div>
                  </Form>
                </div>
              )}
            />
          </div>
        </Drawer>
      </div>
    );
  }
}

ExploreAddWidget.propTypes = {
  onAdd: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ExploreAddWidget);
