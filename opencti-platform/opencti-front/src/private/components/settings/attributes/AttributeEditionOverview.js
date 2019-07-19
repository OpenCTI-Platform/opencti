import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import { ConnectionHandler } from 'relay-runtime';
import Button from '@material-ui/core/Button';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { commitMutation } from '../../../../relay/environment';

const styles = theme => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
});

const attributeMutationUpdate = graphql`
  mutation AttributeEditionOverviewUpdateMutation(
    $id: ID!
    $input: AttributeEditInput!
  ) {
    attributeEdit(id: $id) {
      update(input: $input) {
        ...AttributeLine_attribute
      }
    }
  }
`;

const attributeValidation = t => Yup.object().shape({
  value: Yup.string()
    .required(t('This field is required'))
    .matches(
      /^[a-zA-Z1-9-\s]+$/g,
      t('This field must only contain alphanumeric chars, dashes and space'),
    ),
});

class AttributeEditionOverviewComponent extends Component {
  onSubmit(values, { setSubmitting }) {
    const input = {
      type: this.props.attribute.type,
      value: this.props.attribute.value,
      newValue: values.value,
    };

    commitMutation({
      mutation: attributeMutationUpdate,
      variables: {
        id: this.props.attribute.id,
        input,
      },
      updater: (store) => {
        const container = store.getRoot();
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_attributes',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, this.props.attribute.id);
        const rootField = store.getRootField('attributeEdit');
        const payload = rootField.getLinkedRecord('update', { input });
        const newEdge = payload.setLinkedRecord(payload, 'node');
        ConnectionHandler.insertEdgeBefore(conn, newEdge);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  render() {
    const { t, attribute, classes } = this.props;
    const initialValues = pick(['value'], attribute);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={attributeValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          render={({ submitForm, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                name="value"
                component={TextField}
                label={t('Value')}
                fullWidth={true}
              />
              <div className={classes.buttons}>
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
          )}
        />
      </div>
    );
  }
}

AttributeEditionOverviewComponent.propTypes = {
  attribute: PropTypes.object,
  handleClose: PropTypes.func,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const AttributeEditionOverview = createFragmentContainer(
  AttributeEditionOverviewComponent,
  {
    attribute: graphql`
      fragment AttributeEditionOverview_attribute on Attribute {
        id
        type
        value
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AttributeEditionOverview);
