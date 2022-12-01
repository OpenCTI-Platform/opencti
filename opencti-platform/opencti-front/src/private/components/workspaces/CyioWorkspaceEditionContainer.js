/* eslint-disable */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form, Field } from 'formik';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import MarkDownField from '../../../components/MarkDownField';
import { commitMutation } from '../../../relay/environment';

const styles = (theme) => ({
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    padding: '10px 35px 20px 35px',
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
  dialogTitle: {
    padding: 0,
  },
  dialogContent: {
    padding: 0,
    overflow: 'hidden',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  dialogClosebutton: {
    marginTop: 20,
  },
  title: {
    float: 'left',
  },
});

export const cyioWorkspaceMutationFieldPatch = graphql`
  mutation CyioWorkspaceEditionContainerFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    workspaceEdit(id: $id) {
      fieldPatch(input: $input) {
        ...CyioDashboard_workspace
        ...Investigation_workspace
      }
    }
  }
`;

class CyioWorkspaceEditionContainer extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': n[1],
      })),
    )(values);
    commitMutation({
      mutation: cyioWorkspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.props.history.push('/dashboard/workspaces/dashboards');
        this.props.handleDisplayEdit();
      },
    });
  }

  onReset() {
    this.props.handleDisplayEdit();
  }

  render() {
    const {
      t, classes, workspace, displayEdit,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('name', workspace?.name || ''),
      R.assoc('description', workspace?.description || ''),
      R.pick([
        'name',
        'description',
      ]),
    )(workspace);
    const { editContext } = workspace;
    return (
      <>
        <Dialog
          open={displayEdit}
          keepMounted={true}
          classes={{ paper: classes.drawerPaper }}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            // validationSchema={RelatedTaskValidation(t)}
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
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Edit Dashboard')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
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
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    size='small'
                    onClick={handleReset}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    size='small'
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

CyioWorkspaceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  history: PropTypes.object,
  handleDisplayEdit: PropTypes.func,
  displayEdit: PropTypes.bool,
  classes: PropTypes.object,
  workspace: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const CyioWorkspaceEditionFragment = createFragmentContainer(
  CyioWorkspaceEditionContainer,
  {
    workspace: graphql`
      fragment CyioWorkspaceEditionContainer_workspace on Workspace {
        id
        name
        description
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioWorkspaceEditionFragment);
