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
import Autocomplete from '@material-ui/lab/Autocomplete';
import Search from '@material-ui/icons/Search';
import KeyboardArrowDownIcon from '@material-ui/icons/KeyboardArrowDown';
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
import RolesField from "../../common/form/RolesField";
import LoggedBy from "../../common/form/LoggedBy";
import SelectField from "../../../../components/SelectField";
import { toastGenericError } from "../../../../utils/bakedToast";
import { commitMutation, fetchQuery } from "../../../../relay/environment";
import SearchTextField from "../../common/form/SearchTextField";

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

const informationTypesPopoverQuery = graphql`
  query InformationTypesPopoverQuery($search: String, $filters: [ProductFiltering], $orderedBy: ProductOrdering, $orderMode: OrderingMode) {
    products(search: $search, filters: $filters, orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const informationTypesPopoverIdQuery = graphql`
  query InformationTypesPopoverIdQuery( $id: ID!) {
    product(id: $id) {
      id
      created
      modified
      name
      vendor
      version
      cpe_identifier
      ... on SoftwareProduct {
        software_identifier
      }
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
      openAutocomplete: false,
      products: [],
      productName: '',
      onSubmit: false,
      selectedProduct: {},
      displayCancel: false,
    };
  }

  searchProducts(event, value) {
    this.setState({ productName: value });
    if (event?.type === 'click' && value) {
      const selectedProductValue = this.state.products.filter(
        (product) => product.label === value,
      )[0];
      fetchQuery(informationTypesPopoverIdQuery, {
        id: selectedProductValue.value,
      }).toPromise()
        .then((data) => {
          this.setState({ selectedProduct: data.product });
        });
    }
  }

  handleSearchProducts() {
    this.setState({ selectedProduct: { name: this.state.productName }, openAutocomplete: true });
    (this.state.productName.length > 2) && fetchQuery(informationTypesPopoverQuery, {
      search: this.state.productName,
      orderedBy: 'name',
      orderMode: 'asc',
      filters: [
        { key: 'object_type', values: ['software'] },
      ],
    })
      .toPromise()
      .then((data) => {
        const products = R.pipe(
          R.pathOr([], ['products', 'edges']),
          R.map((n) => ({
            label: n.node.name,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          products: R.union(this.state.products, products),
        });
      })
      .catch((err) => {
        const ErrorResponse = err.res.errors;
        this.setState({ error: ErrorResponse });
      });
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

  handleAutoCompleteClose() {
    this.setState({ openAutocomplete: false })
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.setState({ open: false });
  }

  handleDelete(key) { }

  render() {
    const { t, classes, name, history } = this.props;
    const {
      open,
      selectedProduct,
      openAutocomplete,
      products,
      productName
    } = this.state;
    return (
      <div>
        <div style={{ display: "flex", alignItems: "center" }}>
          <Typography variant="h3" color="textSecondary" gutterBottom={true}>
            {t("Information Type(s)")}
          </Typography>
          <div style={{ float: "left", margin: "5px 0 0 5px" }}>
            <Tooltip title={t("Identifies the details about all information types that are stored, processed, or transmitted by the system, such as privacy information, and those defined in NIST SP 800-60.")}>
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
          maxWidth="md"
          keepMounted={true}
          className={classes.dialogMain}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              name: "",
              description: selectedProduct?.vendor || "",
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
            {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t("Information Type")}
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
                      <SearchTextField
                        name='name'
                        setFieldValue={setFieldValue}
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
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="category"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
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
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="category"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
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
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="category"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
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
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="category"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
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
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="category"
                        fullWidth={true}
                        style={{ height: '38.09px', maxWidth: '300px' }}
                        containerstyle={{ width: '100%' }}
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
              </Form>
            )}
          </Formik>
        </Dialog>
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
