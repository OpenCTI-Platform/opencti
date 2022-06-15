/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import * as Yup from 'yup';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import NoteAddIcon from '@material-ui/icons/NoteAdd';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import AddIcon from '@material-ui/icons/Add';
import { MoreVertOutlined } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM, createFragmentContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import { dateFormat, parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import SelectField from '../../../../../components/SelectField';
import TextField from '../../../../../components/TextField';
import DatePickerField from '../../../../../components/DatePickerField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
import { toastGenericError } from "../../../../../utils/bakedToast";
import LoggedBy from '../../../common/form/LoggedBy';
import RolesField from '../../../common/form/RolesField';

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
    overflowY: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogAction: {
    display: 'flex',
    textAlign: 'end',
    padding: '0 24px',
    justifyContent: 'space-between',
  },
  buttonPopover: {
    margin: '20px 0 20px 10px',
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

const NoteEditionContainerMutation = graphql`
  mutation NoteEntityEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editCyioNote(id: $id, input: $input) {
      id
    }
  }
`;

const NoteValidation = (t) => Yup.object().shape({
  // name: Yup.string().required(t('This field is required')),
});

class NoteEntityEditionContainer extends Component {
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
    this.props.handleDisplayEdit();
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(values);
    CM(environmentDarkLight, {
      mutation: NoteEditionContainerMutation,
      variables: {
        id: this.props.note.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        this.props.refreshQuery();
        resetForm();
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
      t,
      note,
      classes,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('abstract', note?.abstract || ''),
      R.assoc('content', note?.content || ''),
      R.assoc('authors', note?.authors || ''),
      R.pick([
        'abstract',
        'content',
        'authors',
      ]),
    )(note);
    return (
      <>
        <Dialog
          maxWidth='md'
          fullWidth={true}
          keepMounted={true}
          open={this.props.displayEdit}
          className={classes.dialogMain}
          PaperProps={{
            style: {
              overflow: 'hidden',
            },
          }}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={NoteValidation(t)}
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
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Note')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Abstract')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Identifies the identifier defined by the standard.')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name='abstract'
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid xs={12} item={true}>
                      <Field
                        component={MarkDownField}
                        name='content'
                        fullWidth={true}
                        multiline={true}
                        rows='4'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions>
                  <Grid container={true} spacing={3} className={classes.dialogAction}>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Author')}
                      </Typography>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="authors"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
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
                    </Grid>
                  </Grid>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
      </>
    );
  }
}

NoteEntityEditionContainer.propTypes = {
  handleDisplayEdit: PropTypes.func,
  refreshQuery: PropTypes.func,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  connectionKey: PropTypes.string,
  enableReferences: PropTypes.bool,
  note: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(NoteEntityEditionContainer);
