import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { Formik, Field, Form } from 'formik';
import { compose } from 'ramda';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../components/i18n';
import TextField from '../../components/TextField';
import Switch from '../../components/Switch';

const styles = theme => ({
  paper: {
    width: '100%',
    padding: '20px 20px 20px 20px',
    textAlign: 'left',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class Settings extends Component {
  onSubmit(values, { setSubmitting, resetForm, setErrors }) {
    console.log(values);
  }

  render() {
    const { t, classes } = this.props;
    return (
      <Grid container={true} spacing={32}>
        <Grid item={true} xs={9}>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Typography variant='h1' gutterBottom={true}>
              {t('Global')}
            </Typography>
            <Formik
              initialValues={{ title: 'Luatix cyber threat intelligence platform', sender: 'opencti@luatix.org' }}
              onSubmit={this.onSubmit.bind(this)}
              render={({ submitForm, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='title' component={TextField} label={t('Title')} fullWidth={true}/>
                  <Field name='sender' component={TextField} label={t('Sender email address')} fullWidth={true} style={{ marginTop: 20 }}/>
                </Form>
              )}
            />
          </Paper>
        </Grid>
        <Grid item={true} xs={3}>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Typography variant='h1' gutterBottom={true}>
              {t('Options')}
            </Typography>
            <Formik
              initialValues={{ title: 'Luatix cyber threat intelligence platform', external_authentication: true }}
              onSubmit={this.onSubmit.bind(this)}
              render={({ submitForm, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='external_authentication' component={Switch} label={t('External authentication')}/>
                  <Field name='external_authentication' component={Switch} label={t('External authentication')}/>
                </Form>
              )}
            />
          </Paper>
        </Grid>
      </Grid>
    );
  }
}

Settings.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Settings);
