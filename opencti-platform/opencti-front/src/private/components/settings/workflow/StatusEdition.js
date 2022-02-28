import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { compose, pick, pipe, assoc } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { statusCreationStatusTemplatesQuery } from './StatusCreation';

const styles = (theme) => ({
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
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

const statusMutationFieldPatch = graphql`
  mutation StatusEditionFieldPatchMutation(
    $id: ID!
    $statusId: String!
    $input: [EditInput]!
  ) {
    subTypeEdit(id: $id) {
      statusFieldPatch(statusId: $statusId, input: $input) {
        ...SubTypeEdition_subType
      }
    }
  }
`;

const statusValidation = (t) => Yup.object().shape({
  template_id: Yup.string().required(t('This field is required')),
  order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

class StatusEditionContainer extends Component {
  handleSubmitField(name, value) {
    statusValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: statusMutationFieldPatch,
          variables: {
            id: this.props.subTypeId,
            statusId: this.props.status.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, handleClose, open, status } = this.props;
    const initialValues = pipe(
      assoc('template_id', status.template.id),
      pick(['template_id', 'order']),
    )(status);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={statusValidation(t)}
      >
        {() => (
          <Form>
            <Dialog
              open={open}
              PaperProps={{ elevation: 1 }}
              onClose={handleClose.bind(this)}
              fullWidth={true}
            >
              <DialogTitle>{t('Create a status')}</DialogTitle>
              <DialogContent>
                <QueryRenderer
                  query={statusCreationStatusTemplatesQuery}
                  render={({ props }) => {
                    if (props && props.statusTemplates) {
                      const statusTemplatesEdges = props.statusTemplates.edges;
                      const statusTemplates = R.map(
                        (n) => n.node,
                        statusTemplatesEdges,
                      );
                      return (
                        <Field
                          component={SelectField}
                          variant="standard"
                          name="template_id"
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Name')}
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                        >
                          {statusTemplates.map((statusTemplate) => (
                            <MenuItem
                              key={statusTemplate.id}
                              value={statusTemplate.id}
                            >
                              {t(`status_${statusTemplate.name}`)}
                            </MenuItem>
                          ))}
                        </Field>
                      );
                    }
                    return <div />;
                  }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
                  style={{ marginTop: 20 }}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
                <DialogActions>
                  <Button onClick={handleClose.bind(this)}>{t('Close')}</Button>
                </DialogActions>
              </DialogContent>
            </Dialog>
          </Form>
        )}
      </Formik>
    );
  }
}

StatusEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  open: PropTypes.bool,
  classes: PropTypes.object,
  subTypeId: PropTypes.string,
  status: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StatusEditionFragment = createFragmentContainer(StatusEditionContainer, {
  status: graphql`
    fragment StatusEdition_status on Status {
      id
      order
      template {
        id
        name
        color
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(StatusEditionFragment);
