/* eslint-disable */
/* refactor */
import React, { Component } from "react";
import * as PropTypes from "prop-types";
import * as R from "ramda";
import { compose } from "ramda";
import * as Yup from "yup";
import { withStyles } from "@material-ui/core/styles";
import AddIcon from "@material-ui/icons/Add";
import { Formik, Form, Field } from "formik";
import Typography from "@material-ui/core/Typography";
import { Information } from "mdi-material-ui";
import Tooltip from "@material-ui/core/Tooltip";
import graphql from "babel-plugin-relay/macro";
import TextField from "@material-ui/core/TextField";
import Button from "@material-ui/core/Button";
import IconButton from "@material-ui/core/IconButton";
import {
  Dialog,
  DialogContent,
  DialogActions,
  DialogTitle,
  Grid,
  Slide,
} from "@material-ui/core";
import inject18n from "../../../../components/i18n";
import HyperLinks from "../../../../components/HyperLinks";
import MarkDownField from "../../../../components/MarkDownField";
import DatePickerField from "../../../../components/DatePickerField";
import RolesField from "../../common/form/RolesField";
import LoggedBy from "../../common/form/LoggedBy";
import SelectField from "../../../../components/SelectField";
import { toastGenericError } from "../../../../utils/bakedToast";
import { commitMutation } from "../../../../relay/environment";

const styles = (theme) => ({
  dialogMain: {
    overflow: "hidden",
  },
  dialogClosebutton: {
    float: "left",
    marginLeft: "15px",
    marginBottom: "20px",
  },
  dialogTitle: {
    padding: "24px 0 16px 24px",
  },
  dialogActions: {
    justifyContent: "flex-start",
    padding: "10px 0 20px 22px",
  },
  dialogContent: {
    padding: "0 24px",
    marginBottom: "24px",
    overflowY: "scroll",
    height: "650px",
  },
  buttonPopover: {
    textTransform: "capitalize",
  },
  popoverDialog: {
    fontSize: "18px",
    lineHeight: "24px",
    color: theme.palette.header.text,
  },
});

const informationTypesPopoverMutation = graphql`
  mutation InformationTypesPopoverMutation(
    $input: OscalResponsiblePartyAddInput
  ) {
    createOscalResponsibleParty(input: $input) {
      id
    }
  }
`;

const ResponsiblePartyValidation = (t) =>
  Yup.object().shape({
    name: Yup.string().required(t("This field is required")),
  });
const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = "TransitionSlide";

class InformationTypesPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.dissoc("created"),
      R.dissoc("modified"),
      R.dissoc("marking")
    )(values);
    commitMutation({
      mutation: informationTypesPopoverMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      pathname: "/data/entities/responsible_parties",
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.props.history.push("/data/entities/responsible_parties");
      },
      onError: (err) => {
        console.error(err);
        toastGenericError("Failed to create responsible party");
      },
    });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.setState({ open: false });
  }

  handleDelete(key) {}

  render() {
    const { t, classes, name, history } = this.props;
    const { open } = this.state;

    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: "",
            created: null,
            modified: null,
            role: "",
            parties: [],
            marking: [],
          }}
          validationSchema={ResponsiblePartyValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <div style={{ display: "flex", alignItems: "center" }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t("Information Type(s)")}
                </Typography>
                <div style={{ float: "left", margin: "5px 0 0 5px" }}>
                  <Tooltip title={t("Information Type(s)")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <IconButton
                  size="small"
                  onClick={() => this.setState({ open: true })}
                >
                  <AddIcon />
                </IconButton>
              </div>
              <Field
                component={HyperLinks}
                name={name}
                fullWidth={true}
                disabled={true}
                multiline={true}
                rows="3"
                value={[]}
                variant="outlined"
                history={history}
                handleDelete={this.handleDelete.bind(this)}
              />
              <Dialog
                open={open}
                maxWidth='md'
                keepMounted={true}
                className={classes.dialogMain}
                maxWidth='md'
              >
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t('Information Type')}
                </DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Name")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies the identifier defined by the standard."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="name"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: "100%" }}
                        variant="outlined"
                      />
                    </Grid>
                    <Grid xs={12} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Description")}
                      </Typography>
                      <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                        <Tooltip
                          title={t(
                            "Identifies a summary of the reponsible party's purpose and associated responsibilities."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="3"
                        variant="outlined"
                        containerstyle={{ width: "100%" }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: "left" }}
                        >
                          {t("Categorization System")}
                        </Typography>
                        <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                          <Tooltip
                            title={t(
                              "Identifies a reference to the role that the party is responsible for."
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <RolesField
                          variant="outlined"
                          name="role"
                          size="small"
                          fullWidth={true}
                          style={{ height: "38.09px", marginBottom: "3px" }}
                          containerstyle={{
                            width: "100%",
                            padding: "0 0 1px 0",
                          }}
                        />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Category")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip title={t("Marking")}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant="outlined"
                        name="marking"
                        fullWidth={true}
                        style={{ height: "38.09px" }}
                        containerstyle={{ width: "100%" }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Information Type")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <LoggedBy
                        variant="outlined"
                        name="parties"
                        size="small"
                        fullWidth={true}
                        multiple={true}
                        style={{ height: "38.09px", marginBottom: "3px" }}
                        containerstyle={{ width: "100%", padding: "0 0 1px 0" }}
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Confidentiality Impact")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                    </Grid>
                    <Grid item={true} xs={2}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Base")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                    </Grid>
                    <Grid item={true} xs={2}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Selected")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <LoggedBy
                        variant="outlined"
                        name="parties"
                        size="small"
                        fullWidth={true}
                        multiple={true}
                        style={{ height: "38.09px", marginBottom: "3px" }}
                        containerstyle={{ width: "100%", padding: "0 0 1px 0" }}
                      />
                    </Grid>
                    <Grid xs={8} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Justification")}
                      </Typography>
                      <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                        <Tooltip
                          title={t(
                            "Identifies a summary of the reponsible party's purpose and associated responsibilities."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="1"
                        variant="outlined"
                        containerstyle={{ width: "100%" }}
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Integrity Impact")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                    </Grid>
                    <Grid item={true} xs={2}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Base")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />                      
                    </Grid>
                    <Grid item={true} xs={2}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Selected")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <LoggedBy
                        variant="outlined"
                        name="parties"
                        size="small"
                        fullWidth={true}
                        multiple={true}
                        style={{ height: "38.09px", marginBottom: "3px" }}
                        containerstyle={{ width: "100%", padding: "0 0 1px 0" }}
                      />
                    </Grid>
                    <Grid xs={8} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Justification")}
                      </Typography>
                      <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                        <Tooltip
                          title={t(
                            "Identifies a summary of the reponsible party's purpose and associated responsibilities."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="3"
                        variant="outlined"
                        containerstyle={{ width: "100%" }}
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Availability Impact")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                    </Grid>
                    <Grid item={true} xs={2}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Base")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                    </Grid>
                    <Grid item={true} xs={2}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Selected")}
                      </Typography>
                      <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                        <Tooltip
                          title={t(
                            "Identifies one or more references to the parties that are responsible for performing the associated role."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <LoggedBy
                        variant="outlined"
                        name="parties"
                        size="small"
                        fullWidth={true}
                        multiple={true}
                        style={{ height: "38.09px", marginBottom: "3px" }}
                        containerstyle={{ width: "100%", padding: "0 0 1px 0" }}
                      />
                    </Grid>
                    <Grid xs={8} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: "left" }}
                      >
                        {t("Justification")}
                      </Typography>
                      <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                        <Tooltip
                          title={t(
                            "Identifies a summary of the reponsible party's purpose and associated responsibilities."
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="3"
                        variant="outlined"
                        containerstyle={{ width: "100%" }}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    onClick={handleReset}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t("Cancel")}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t("Submit")}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    );
  }
}

InformationTypesPopover.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(InformationTypesPopover);
