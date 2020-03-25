import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { compose, pick } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import { TextField } from 'formik-material-ui';
import * as Yup from 'yup';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
});

const attributeMutationUpdate = graphql`
  mutation AttributeEditionUpdateMutation(
    $id: ID!
    $input: AttributeEditInput!
  ) {
    attributeEdit(id: $id) {
      update(input: $input) {
        ...AttributeEdition_attribute
      }
    }
  }
`;

const attributeValidation = (t) => Yup.object().shape({
  value: Yup.string().required(t('This field is required')),
});

class AttributeEditionContainer extends Component {
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
      optimisticUpdater: (store) => {
        // Artificially remove of a line to force refresh in the updater.
        // Attribute like this should have stable UUID.
        const container = store.getRoot();
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_attributes',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, this.props.attribute.id);
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
        const payload = store
          .getRootField('attributeEdit')
          .getLinkedRecord('update', { input });
        const newEdge = ConnectionHandler.createEdge(
          store,
          conn,
          payload,
          'AttributeEdge',
        );
        ConnectionHandler.insertEdgeAfter(conn, newEdge);
        this.props.handleClose();
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
      },
    });
  }

  render() {
    const {
      t, classes, handleClose, attribute,
    } = this.props;
    const initialValues = pick(['value'], attribute);
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an attribute')}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={attributeValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
          >
            {({ submitForm, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="value"
                  label={t('Type')}
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
          </Formik>
        </div>
      </div>
    );
  }
}

AttributeEditionContainer.propTypes = {
  paginationOptions: PropTypes.object,
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  attribute: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const AttributeEditionFragment = createFragmentContainer(
  AttributeEditionContainer,
  {
    attribute: graphql`
      fragment AttributeEdition_attribute on Attribute {
        id
        type
        value
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(AttributeEditionFragment);
