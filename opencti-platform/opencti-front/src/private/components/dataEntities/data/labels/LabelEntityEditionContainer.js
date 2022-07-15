/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import * as Yup from 'yup';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Button from '@material-ui/core/Button';
import DialogTitle from '@material-ui/core/DialogTitle';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import TextField from '../../../../../components/TextField';
import ColorPickerField from '../../../../../components/ColorPickerField';
import { toastGenericError } from "../../../../../utils/bakedToast";


const styles = (theme) => ({
  dialogMain: {
    overflow: 'hidden',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflow: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
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
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

const labelEntityEditionContainerMutation = graphql`
  mutation LabelEntityEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editCyioLabel(id: $id, input: $input) {
      id
    }
  }
`;

const EntityLabelValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

class LabelEntityEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      details: false,
      close: false,
      onSubmit: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleSubmit() {
    this.setState({ onSumbit: true });
  }

  onReset() {
    this.handleClose();
    this.props.handleDisplayEdit();
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = R.evolve(
      {
        modified: () => values.modified === null ? null : parse(values.modified).format(),
        created: () => values.created === null ? null : parse(values.created).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    commitMutation({
      mutation: labelEntityEditionContainerMutation,
      variables: {
        id: this.props.label.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/data/entities/labels');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Request Failed');
      }
    });
    this.setState({ onSubmit: true });
  }

  render() {
    const {
      classes,
      t,
      label,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('name', label?.name || ''),
      R.assoc('description', label?.description || ''),
      R.assoc('color', label?.color || ''),
      R.pick([
        'name',
        'description',
        'color',
      ]),
    )(label);
    return (
      <>
        <Dialog
          maxWidth='sm'
          fullWidth={true}
          keepMounted={true}
          open={this.props.displayEdit}
          className={classes.dialogMain}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={EntityLabelValidation(t)}
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
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Label')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Label')}
                    fullWidth={true}
                    style={{ marginBottom: 10 }}
                  />
                  <Field
                    component={TextField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t('Color')}
                    fullWidth={true}
                    style={{ marginTop: 10 }}
                  />
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

LabelEntityEditionContainer.propTypes = {
  handleDisplayEdit: PropTypes.func,
  label: PropTypes.object,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  disabled: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
  connectionKey: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(LabelEntityEditionContainer);
