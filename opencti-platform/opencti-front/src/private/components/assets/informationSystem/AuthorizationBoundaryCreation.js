/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose, pathOr } from 'ramda';
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
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import HyperLinkField from '../../common/form/HyperLinkField';
import SystemDocumentationDiagram from '../../common/form/SystemDocumentationDiagram';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';

const styles = (theme) => ({
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'auto',
    overflowX: 'hidden',
    // minWidth: '580px',
    minHeight: '550px',
  },
  dialogClosebutton: {
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
});

const authorizationBoundaryCreationMutation = graphql`
  mutation AuthorizationBoundaryCreationMutation($input: DescriptionBlockInput!) {
    createDescriptionBlock (input: $input) {
      id
    }
  }
`;

class AuthorizationBoundaryCreation extends Component {
  onReset() {
    this.props.handleCloseCreate();
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    commitMutation({
      mutation: authorizationBoundaryCreationMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      pathname: '/defender_hq/assets/information_systems',
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.props.history.push('/defender_hq/assets/information_systems');
      },
      onError: () => {
        toastGenericError('Failed to create Authorization Boundary');
      },
    });
  }

  render() {
    const {
      t,
      classes,
      openCreate,
    } = this.props;
    return (
      <>
        <Dialog
          open={openCreate}
          keepMounted={true}
        >
          <Formik
            initialValues={{
              description: '',
              diagram: [],
            }}
            enableReinitialize={true}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({
              values,
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t('Create Authorization Boundary')}
                </DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography>
                        {t("Identifies a description of this system's authorization boundary, optionally supplemented by diagrams that illustrate the authorization boundary.")}
                      </Typography>
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
                      <SystemDocumentationDiagram
                        setFieldValue={setFieldValue}
                        values={values}
                        diagramType='authorization_type'
                        title='Diagram(s)'
                        name='diagram'
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <CyioCoreObjectExternalReferences
                        disableAdd={true}
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

AuthorizationBoundaryCreation.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  openCreate: PropTypes.bool,
  handleCloseCreate: PropTypes.func,

};

export default compose(inject18n, withStyles(styles))(AuthorizationBoundaryCreation);
