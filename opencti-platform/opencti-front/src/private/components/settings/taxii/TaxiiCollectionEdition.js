import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { compose, pickAll } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';

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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
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
});

const taxiiCollectionMutationFieldPatch = graphql`
  mutation TaxiiCollectionEditionFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    taxiiCollectionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...TaxiiCollectionEdition_taxiiCollection
      }
    }
  }
`;

const taxiiCollectionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

class TaxiiCollectionEditionContainer extends Component {
  handleSubmitField(name, value) {
    taxiiCollectionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: taxiiCollectionMutationFieldPatch,
          variables: {
            id: this.props.taxiiCollection.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, taxiiCollection,
    } = this.props;
    const initialValues = pickAll(
      ['name', 'description'],
      taxiiCollection,
    );
    console.log(initialValues);

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
            {t('Update a taxii collection')}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={taxiiCollectionValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="name"
                  label={t('Collection name')}
                  fullWidth={true}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
                <Field
                  component={TextField}
                  name="description"
                  label={t('Collection description')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
              </Form>
            )}
          </Formik>
        </div>
      </div>
    );
  }
}

TaxiiCollectionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  taxiiCollection: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const TaxiiCollectionEditionFragment = createFragmentContainer(
  TaxiiCollectionEditionContainer,
  {
    taxiiCollection: graphql`
      fragment TaxiiCollectionEdition_taxiiCollection on TaxiiCollection {
        id
        name
        description
        filters
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(TaxiiCollectionEditionFragment);
