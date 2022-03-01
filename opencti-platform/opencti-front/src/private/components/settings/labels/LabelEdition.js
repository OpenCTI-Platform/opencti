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
  subscription LabelEditionSubscription($id: ID!) {
    label(id: $id) {
      ...LabelEdition_label
    }
  }
`;

const labelMutationFieldPatch = graphql`
  mutation LabelEditionFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    labelEdit(id: $id) {
      fieldPatch(input: $input) {
        ...LabelEdition_label
      }
    }
  }
`;

const labelEditionFocus = graphql`
  mutation LabelEditionFocusMutation($id: ID!, $input: EditContext!) {
    labelEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const labelValidation = (t) => Yup.object().shape({
  value: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

class LabelEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.label.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: labelEditionFocus,
      variables: {
        id: this.props.label.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    labelValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: labelMutationFieldPatch,
          variables: {
            id: this.props.label.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, classes, handleClose, label } = this.props;
    const { editContext } = label;
    const initialValues = pick(['value', 'color'], label);
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
            {t('Update a label')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={labelValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="value"
                  label={t('Value')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="value"
                    />
                  }
                />
                <Field
                  component={ColorPickerField}
                  name="color"
                  label={t('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="color"
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

LabelEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  label: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const LabelEditionFragment = createFragmentContainer(LabelEditionContainer, {
  label: graphql`
    fragment LabelEdition_label on Label {
      id
      value
      color
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(LabelEditionFragment);
