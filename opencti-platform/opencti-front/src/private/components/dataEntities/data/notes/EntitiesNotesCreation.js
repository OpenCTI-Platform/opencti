/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose, evolve } from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import DialogContent from '@material-ui/core/DialogContent';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import { toastGenericError } from '../../../../../utils/bakedToast';

const styles = (theme) => ({
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  dialogContent: {
    padding: '0 24px',
    overflow: 'hidden',
    marginBottom: '24px',
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
  dialogAction: {
    display: 'flex',
    textAlign: 'end',
    padding: '0 24px',
    justifyContent: 'space-between',
  },
});

const entitiesNotesCreationMutation = graphql`
  mutation EntitiesNotesCreationMutation($input: CyioNoteAddInput) {
    createCyioNote (input: $input) {
      id
    }
  }
`;

const NoteValidation = (t) => Yup.object().shape({
  // name: Yup.string().required(t('This field is required')),
});
const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class EntitiesNotesCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
    };
  }

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  handleOpen() {
    this.setState({ open: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.assoc('authors', values.authors),
    )(values);
    CM(environmentDarkLight, {
      mutation: entitiesNotesCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.props.history.push('/data/entities/notes');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Failed to create new note');
      },
    });
    // commitMutation({
    //   mutation: entitiesNotesCreationMutation,
    //   variables: {
    //     input: values,
    //   },
    // //   // updater: (store) => insertNode(
    // //   //   store,
    // //   //   'Pagination_threatActors',
    // //   //   this.props.paginationOptions,
    // //   //   'threatActorAdd',
    // //   // ),
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.props.handleNoteCreation();
  }

  render() {
    const {
      t,
      classes,
      openDataCreation,
      handleNoteCreation,
      open,
      me,
      history,
    } = this.props;
    return (
      <>
        <Dialog
          maxWidth='md'
          fullWidth={true}
          keepMounted={true}
          open={openDataCreation}
          PaperProps={{
            style: {
              overflow: 'hidden',
            },
          }}
        >
          <Formik
            enableReinitialize={true}
            style={{ overflow: 'hidden' }}
            initialValues={{
              abstract: '',
              content: '',
              authors: me.name,
            }}
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
                        name="abstract"
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

EntitiesNotesCreation.propTypes = {
  openDataCreation: PropTypes.bool,
  handleNoteCreation: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  me: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(EntitiesNotesCreation);
