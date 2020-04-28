import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { compose, pick } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
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

const subscription = graphql`
  subscription TagEditionSubscription($id: ID!) {
    tag(id: $id) {
      ...TagEdition_tag
    }
  }
`;

const tagMutationFieldPatch = graphql`
  mutation TagEditionFieldPatchMutation($id: ID!, $input: EditInput!) {
    tagEdit(id: $id) {
      fieldPatch(input: $input) {
        ...TagEdition_tag
      }
    }
  }
`;

const tagEditionFocus = graphql`
  mutation TagEditionFocusMutation($id: ID!, $input: EditContext!) {
    tagEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const tagValidation = (t) => Yup.object().shape({
  tag_type: Yup.string().required(t('This field is required')),
  definition: Yup.string().required(t('This field is required')),
  value: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

class TagEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: { id: this.props.tag.id },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: tagEditionFocus,
      variables: {
        id: this.props.tag.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    tagValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: tagMutationFieldPatch,
          variables: {
            id: this.props.tag.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, tag,
    } = this.props;
    const { editContext } = tag;
    const initialValues = pick(['tag_type', 'value', 'color'], tag);
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
            {t('Update a tag')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={tagValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="tag_type"
                  label={t('Type')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="tag_type"
                    />
                  }
                />
                <Field
                  component={TextField}
                  name="value"
                  label={t('Value')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
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

TagEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  tag: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const TagEditionFragment = createFragmentContainer(TagEditionContainer, {
  tag: graphql`
    fragment TagEdition_tag on Tag {
      id
      tag_type
      value
      color
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(TagEditionFragment);
