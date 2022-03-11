/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../components/i18n';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import NoteAddIcon from '@material-ui/icons/NoteAdd';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import SelectField from '../components/SelectField';

const styles = (theme) => ({
    dialogRoot: {
        padding: '24px',
        overflowY: 'hidden',
    },
    button: {
        display: 'table-cell',
        float: 'left',
    },
    buttonPopover: {
        textTransform: 'capitalize',
    },
    dialogContent: {
        overflowY: 'hidden',
    },
    popoverDialog: {
        fontSize: '18px',
        lineHeight: '24px',
        color: theme.palette.header.text,
    },
    dialogActions: {
        justifyContent: 'flex-start',
        padding: '10px 0 20px 22px',
    },
});

class Export extends Component {
    constructor(props) {
        super(props);
        this.state = {
            open: false,
            close: false,
        };
    }

    handleClickOpen = () => {
        this.setState({ open: true });
    };

    handleClose = () => {
        this.setState({ open: false });
    };

    handleCancelClick() {
        this.setState({
            open: false,
            close: true,
        });
    }

    handleCancelCloseClick() {
        this.setState({ close: false });
    }

    onSubmit(values, { setSubmitting, resetForm }) {
        console.log('relatedTask', values);
        // this.setState({
        //   timings: {
        //     start_date: values.start_date === null ? null : parse(values.start_date).format(),
        //     end_date: values.end_date === null ? null : parse(values.end_date).format(),
        //   },
        // });
        // const finalValues = pipe(
        //   dissoc('start_date'),
        //   dissoc('end_date'),
        //   dissoc('related_tasks'),
        //   assoc('timings', this.state.timings),
        //   dissoc('timings'),
        //   dissoc('milestone'),
        //   // assoc('responsible_roles', this.state.responsible_roles),
        // )(values);
        // CM(environmentDarkLight, {
        //   mutation: RelatedTaskCreationMutation,
        //   variables: {
        //     input: finalValues,
        //   },
        //   // updater: (store) => insertNode(
        //   //   store,
        //   //   'Pagination_externalReferences',
        //   //   this.props.paginationOptions,
        //   //   'externalReferenceAdd',
        //   // ),
        //   setSubmitting,
        //   onCompleted: (response) => {
        //     console.log('relatedTasksCreationResponse', response);
        //     setSubmitting(false);
        //     resetForm();
        //     this.handleClose();
        //   },
        //   onError: (err) => console.log('finalValuesRelatedTasksError', err),
        // });
        // // commitMutation({
        // //   mutation: RelatedTaskCreationMutation,
        // //   variables: {
        // //     input: values,
        // //   },
        // //   updater: (store) => insertNode(
        // //     store,
        // //     'Pagination_externalReferences',
        // //     this.props.paginationOptions,
        // //     'externalReferenceAdd',
        // //   ),
        // //   setSubmitting,
        // //   onCompleted: (response) => {
        // //     setSubmitting(false);
        // //     resetForm();
        // //     this.handleClose();
        // //     if (this.props.onCreate) {
        // //       this.props.onCreate(response.externalReferenceAdd, true);
        // //     }
        // //   },
        // // });
    }

    onResetContextual() {
        this.handleClose();
    }

    render() {
        const {
            t, classes, location, history, keyword, theme,
        } = this.props;
        return (
            <>
                <IconButton classes={{ root: classes.button }} onClick={this.handleClickOpen.bind(this)}>
                    <NoteAddIcon fontSize="default" />
                </IconButton>
                <Formik
                    enableReinitialize={true}
                    initialValues={{
                        format: '',
                        level: '',
                    }}
                    // validationSchema={RelatedTaskValidation(t)}
                    onSubmit={this.onSubmit.bind(this)}
                    onReset={this.onResetContextual.bind(this)}
                >
                    {({ submitForm, handleReset, isSubmitting }) => (
                        <Dialog
                            classes={{ root: classes.dialogRoot }}
                            open={this.state.open}
                            onClose={this.handleClose.bind(this)}
                            fullWidth={true}
                            maxWidth='md'
                        >
                            <Form>
                                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Export')}</DialogTitle>
                                <DialogContent classes={{ root: classes.dialogContent }}>
                                    <Grid container={true} spacing={3}>
                                        <Grid item={true} xs={12}>
                                            <div>
                                                <div className="clearfix" />
                                                <Field
                                                    component={SelectField}
                                                    name="task_type"
                                                    fullWidth={true}
                                                    variant='standard'
                                                    label='Format'
                                                    style={{ height: '38.09px' }}
                                                    containerstyle={{ width: '100%' }}
                                                >
                                                    <MenuItem value='milestone'>
                                                        Milestone
                                                    </MenuItem>
                                                    <MenuItem value='action'>
                                                        Action
                                                    </MenuItem>
                                                    <MenuItem value='query'>
                                                        Query
                                                    </MenuItem>
                                                    <MenuItem value='list'>
                                                        List
                                                    </MenuItem>
                                                    <MenuItem value='ruke'>
                                                        Rule
                                                    </MenuItem>
                                                </Field>
                                            </div>
                                        </Grid>
                                        <Grid item={true} xs={12}>
                                            <div>
                                                <div className="clearfix" />
                                                <Field
                                                    component={SelectField}
                                                    name="task_type"
                                                    fullWidth={true}
                                                    variant='standard'
                                                    label='Max Marking Definition Level'
                                                    style={{ height: '38.09px' }}
                                                    containerstyle={{ width: '100%' }}
                                                >
                                                    <MenuItem value='milestone'>
                                                        Milestone
                                                    </MenuItem>
                                                    <MenuItem value='action'>
                                                        Action
                                                    </MenuItem>
                                                    <MenuItem value='query'>
                                                        Query
                                                    </MenuItem>
                                                    <MenuItem value='list'>
                                                        List
                                                    </MenuItem>
                                                    <MenuItem value='ruke'>
                                                        Rule
                                                    </MenuItem>
                                                </Field>
                                            </div>
                                        </Grid>
                                        <Grid item={true} xs={9}>
                                            <Typography style={{ marginTop: '15px' }}>{t('An email with a download link will be sent to your email')}</Typography>
                                        </Grid>
                                        <Grid item={true} xs={3}>
                                            <DialogActions>
                                                <Button
                                                    variant="outlined"
                                                    // onClick={handleReset}
                                                    onClick={this.handleCancelClick.bind(this)}
                                                    disabled={isSubmitting}
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
                                        </Grid>
                                    </Grid>
                                </DialogContent>
                            </Form>
                        </Dialog>
                    )}
                </Formik>
            </>
        );
    }
}

Export.propTypes = {
    keyword: PropTypes.string,
    theme: PropTypes.object,
    classes: PropTypes.object,
    location: PropTypes.object,
    t: PropTypes.func,
    history: PropTypes.object,
};

export default compose(
    inject18n,
    withStyles(styles),
)(Export);

