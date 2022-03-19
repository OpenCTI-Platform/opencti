import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { compose, pick } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';

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

const subscription = graphql`
  subscription MarkingDefinitionEditionSubscription($id: ID!) {
    markingDefinition(id: $id) {
      ...MarkingDefinitionEdition_markingDefinition
    }
  }
`;

const markingDefinitionMutationFieldPatch = graphql`
  mutation MarkingDefinitionEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    markingDefinitionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...MarkingDefinitionEdition_markingDefinition
      }
    }
  }
`;

const markingDefinitionEditionFocus = graphql`
  mutation MarkingDefinitionEditionFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    markingDefinitionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const markingDefinitionValidation = (t) => Yup.object().shape({
  definition_type: Yup.string().required(t('This field is required')),
  definition: Yup.string().required(t('This field is required')),
  x_opencti_color: Yup.string().required(t('This field is required')),
  x_opencti_order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

class MarkingDefinitionEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.markingDefinition.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: markingDefinitionEditionFocus,
      variables: {
        id: this.props.markingDefinition.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    markingDefinitionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: markingDefinitionMutationFieldPatch,
          variables: {
            id: this.props.markingDefinition.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, classes, handleClose, markingDefinition } = this.props;
    const { editContext } = markingDefinition;
    const initialValues = pick(
      ['definition_type', 'definition', 'x_opencti_color', 'x_opencti_order'],
      markingDefinition,
    );
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a marking definition')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={markingDefinitionValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="definition_type"
                  label={t('Type')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="definition_type"
                    />
                  }
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="definition"
                  label={t('Definition')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="definition"
                    />
                  }
                />
                <Field
                  component={ColorPickerField}
                  name="x_opencti_color"
                  label={t('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_color"
                    />
                  }
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="x_opencti_order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_order"
                    />
                  }
                />
              </Form>
            )}
          </Formik>
        </div>
      </div>
    );
  }
}

MarkingDefinitionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  markingDefinition: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const MarkingDefinitionEditionFragment = createFragmentContainer(
  MarkingDefinitionEditionContainer,
  {
    markingDefinition: graphql`
      fragment MarkingDefinitionEdition_markingDefinition on MarkingDefinition {
        id
        definition_type
        definition
        x_opencti_color
        x_opencti_order
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
  withStyles(styles),
)(MarkingDefinitionEditionFragment);
