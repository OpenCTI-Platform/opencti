/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
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
import { adaptFieldValue } from '../../../../utils/String';
import MarkDownField from '../../../../components/MarkDownField';
import HyperLinkField from '../../common/form/HyperLinkField';
import { commitMutation } from '../../../../relay/environment';
import { toastGenericError } from '../../../../utils/bakedToast';
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
  buttonPopover: {
    textTransform: 'capitalize',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
});

const authorizationBoundaryEditionMutation = graphql`
  mutation AuthorizationBoundaryEditionPopovernMutation($id: ID!, $input: [EditInput]!) {
    editDescriptionBlock (id: $id, input: $input) {
      id
    }
  }
`;

class AuthorizationBoundaryEdition extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => {
        return {
          'key': n[0],
          'value': Array.isArray(adaptFieldValue(n[1])) ? adaptFieldValue(n[1]) : [adaptFieldValue(n[1])],
        }
      }),
    )(values);
    commitMutation({
      mutation: authorizationBoundaryEditionMutation,
      variables: {
        id: this.props.informationSystem.id,
        input: finalValues,
      },
      setSubmitting,
      pathname: '/defender_hq/assets/information_systems',
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.props.history.push('/defender_hq/assets/information_systems');
      },
      onError: () => {
        toastGenericError('Failed to edit Data Flow');
      },
    });
  }

  onReset() {
    this.props.handleCloseEdit();
  }

  render() {
    const {
      t,
      classes,
      refreshQuery,
      informationSystem,
    } = this.props;
    const authorizationBoundary = R.pathOr([], ['authorization_boundary'], informationSystem);
    const initialValues = R.pipe(
      R.assoc('description', authorizationBoundary?.description || ''),
      R.assoc('diagram', authorizationBoundary?.diagram || []),
      R.pick([
        'diagram',
        'description',
      ]),
    )(authorizationBoundary);
    return (
      <>
        <Dialog open={this.props.openEdit} keepMounted={true}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
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
                  {t('Edit Authorization Boundary')}
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
                        diagramType='authorization_boundary'
                        title='Diagram(s)'
                        id={informationSystem.id}
                        name='diagram'
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <CyioCoreObjectExternalReferences
                        externalReferences={authorizationBoundary.links}
                        cyioCoreObjectId={authorizationBoundary.id}
                        fieldName='links'
                        refreshQuery={refreshQuery}
                        typename={authorizationBoundary.__typename}
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

AuthorizationBoundaryEdition.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  handleCloseEdit: PropTypes.func,
};

const AuthorizationBoundaryEditionPopover = createFragmentContainer(AuthorizationBoundaryEdition, {
  informationSystem: graphql`
    fragment AuthorizationBoundaryEditionPopover_information on InformationSystem {
      __typename
      id
      authorization_boundary {
        id
        entity_type
        description
        links {
          id
          entity_type
          created
          modified
          source_name
          description
          url
          external_id
          reference_purpose
          media_type
        }
      }
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(AuthorizationBoundaryEditionPopover);
