/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import * as Yup from 'yup';
import { Formik, Form, Field } from 'formik';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Edit from '@material-ui/icons/Edit';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Switch from '@material-ui/core/Switch';
import { Button, IconButton } from '@material-ui/core';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import SwitchField from '../../../../components/SwitchField';
import CyioCoreObjectLabelsView from '../../common/stix_core_objects/CyioCoreObjectLabelsView';
import MarkDownField from '../../../../components/MarkDownField';
import { adaptFieldValue } from '../../../../utils/String';

const styles = (theme) => ({
  paper: {
    height: '97%',
    minHeight: '50%',
    marginTop: '2%',
    padding: '1.5rem',
    borderRadius: 6,
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    textAlign: 'left',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '165px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  thumb: {
    '&.MuiSwitch-thumb': {
      color: 'white',
    },
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  switch_track: {
    backgroundColor: '#D3134A !important',
    opacity: '1 !important',
  },
  switch_base: {
    color: 'white',
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC !important',
      opacity: 1,
    },
  },
});

const riskOverviewEditMutation = graphql`
  mutation RiskOverviewEditMutation($id: ID!, $input: [EditInput]!) {
    editRisk(id: $id, input: $input) {
      id
      accepted
      false_positive
      risk_adjusted
      justification
    }
  }
`;

const RiskValidation = (t) => Yup.object().shape({
  false_positive: Yup.string().nullable(),
  risk_adjusted: Yup.string().nullable(),
  accepted: Yup.string().nullable(),
});

class RiskOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      modelName: '',
    };
  }

  handleEditOpen(field) {
    this.setState({ open: !this.state.open, modelName: field });
  }

  handleSubmitField(name, value) {
    RiskValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: riskOverviewEditMutation,
          variables: { id: this.props.risk.id, input: { key: name, value } },
          onCompleted: () => {
            this.setState({ modelName: '', open: false });
          },
        });
      })
      .catch(() => false);
  }
  
  submitJustification(values, { setSubmitting }) {
    const adaptedValues = R.evolve(
      {
        justification: () => values.justification !== "" ? [values.justification] : [this.props.risk.justification],
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => {

          if(n[0] === "justification" && values.justification === "") {
            return {
            'key': n[0],
            'value': [this.props.risk.justification],
            'operation': 'remove',
            }
          }
          return {
            'key': n[0],
            'value': adaptFieldValue(n[1]),
          }
        }
      ),
    )(adaptedValues)
    commitMutation({
      mutation: riskOverviewEditMutation,
      variables: { 
        id: this.props.risk.id, 
        input: finalValues,
         
      },
      onCompleted: () => {
        this.setState({ modelName: '', open: false });
      },
    });
  }

  renderJustification() {
    const {
      t, fldt, classes, risk, refreshQuery,
    } = this.props;
    const {
      open,
      modelName,
    } = this.state;
    const initialValues = R.pipe(
      R.assoc('justification', risk?.justification || ""),
      R.pick([
        'justification',
      ]),
    )(risk);
    return (
      <Formik enableReinitialize={true} initialValues={initialValues} onSubmit={this.submitJustification.bind(this)}>
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <div className={classes.textBase}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ margin: 0 }}
            >
              {t('Justification')}
            </Typography>
            <Tooltip
              title={t(
                'Identifies a summary of impact for how the risk affects the system.',
              )}
            >
              <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
            </Tooltip>
            <IconButton
                size="small"
                style={{ fontSize: "15px" }}
                color={
                  open && modelName === "justification"
                    ? "primary"
                    : "inherit"
                }
                onClick={this.handleEditOpen.bind(this, "justification")}
              >
                <Edit fontSize="inherit" />
              </IconButton>                 
          </div>
          <div className="clearfix" />
          {open && modelName === "justification" 
          ? 
          <>
            <Field
              component={MarkDownField}
              name='justification'
              fullWidth={true}
              multiline={true}
              variant='outlined'
            />
            <div style={{ marginTop: '20px' }}>
              <Button 
                
                variant="outlined"
                size="small"
                onClick={() => this.setState({ open: !this.state.open, modelName: 'justification' })}
                style={{ marginRight: '10px' }}
              >
                Cancel
              </Button>
              <Button 
                onClick={submitForm}
                variant="contained"
                color="primary"
                size="small"
              >
                Submit
              </Button>
            </div> 
          </>                        
              : (
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {risk.justification && t(risk.justification)}
                  </div>
                </div>
              </div>
            )}            
        </Form>
      )}
    </Formik>
    )
  }

  render() {
    const {
      t, fldt, classes, risk, refreshQuery,
    } = this.props;
    const {
      open,
      modelName,
    } = this.state;
    const initialValues = R.pipe(
      R.assoc('risk_adjusted', risk?.risk_adjusted || false),
      R.assoc('false_positive', risk?.false_positive || false),
      R.assoc('accepted', risk?.accepted || false),
      R.pick([
        'false_positive',
        'risk_adjusted',
        'accepted',
      ]),
    )(risk);
    const enableJustification = R.compose(
      R.values,
      R.filter((item) => item)
     )(initialValues);
    return (
      <div style={{ height: "100%" }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t("Basic Information")}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Formik enableReinitialize={true} initialValues={initialValues}>
          <Form>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("ID")}
                    </Typography>
                    <Tooltip title={t("Uniquely identifies this object")}>
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.id && t(risk.id)}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Created")}
                    </Typography>
                    <Tooltip
                      title={t(
                        "Indicates the date and time at which the object was originally created."
                      )}
                    >
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.created && fldt(risk.created)}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Modified")}
                    </Typography>
                    <Tooltip
                      title={t(
                        "Indicates the date and time that this particular version of the object was last modified."
                      )}
                    >
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.modified && fldt(risk.modified)}
                </Grid>
                <Grid item={true} xs={12}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Description")}
                    </Typography>
                    <Tooltip
                      title={t(
                        "Identifies a human-readable summary of the identified risk, to include a statement of how the risk impacts the system."
                      )}
                    >
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                        <Markdown
                          remarkPlugins={[remarkGfm, remarkParse]}
                          rehypePlugins={[rehypeRaw]}
                          parserOptions={{ commonmark: true }}
                          className="markdown"
                        >
                          {risk.description && t(risk.description)}
                        </Markdown>
                      </div>
                    </div>
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Risk Rating")}
                    </Typography>
                    <Tooltip title={t("Risk Rating")}>
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.risk_level && t(risk.risk_level)}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Priority")}
                    </Typography>
                    <Tooltip
                      title={t(
                        "Identifies Assessor's recommended risk priority. Lower numbers are higher priority. One (1) is highest priority."
                      )}
                    >
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.priority && t(risk.priority)}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Impact")}
                    </Typography>
                    <Tooltip title={t("Version")}>
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {/* {risk.impact && t(risk.impact)} */}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Likelihood")}
                    </Typography>
                    <Tooltip title={t("Likelihood")}>
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {/* {risk.likelihood && t(risk.likelihood)} */}
                </Grid>
                <Grid item={true} xs={4}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Accepted")}
                    </Typography>
                    <Tooltip title={t("Accepted")}>
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                    <IconButton
                      size="small"
                      style={{ fontSize: "15px" }}
                      color={
                        open && modelName === "accepted" ? "primary" : "inherit"
                      }
                      onClick={this.handleEditOpen.bind(this, "accepted")}
                    >
                      <Edit fontSize="inherit" />
                    </IconButton>
                  </div>
                  <div className="clearfix" />
                  <div style={{ display: "flex" }}>
                    <Typography
                      style={{ display: "flex", alignItems: "center" }}
                    >
                      No
                    </Typography>
                    {open && modelName === "accepted" ? (
                      <Field
                        component={SwitchField}
                        name="accepted"
                        type='checkbox'
                        containerstyle={{ margin: "0 -15px 0 11px" }}
                        onChange={this.handleSubmitField.bind(this)}
                      />
                    ) : (
                      <Switch
                        disabled
                        defaultChecked={risk.accepted}
                        classes={{
                          thumb: classes.thumb,
                          track: classes.switch_track,
                          switchBase: classes.switch_base,
                        }}
                      />
                    )}
                    <Typography
                      style={{ display: "flex", alignItems: "center" }}
                    >
                      Yes
                    </Typography>
                  </div>
                </Grid>
                <Grid item={true} xs={4}>
                  <div>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t("False Positive")}
                      </Typography>
                      <Tooltip
                        title={t(
                          "Identifies that the risk has been confirmed to be a false positive."
                        )}
                      >
                        <Information
                          style={{ marginLeft: "5px" }}
                          fontSize="inherit"
                          color="disabled"
                        />
                      </Tooltip>
                      <IconButton
                        size="small"
                        style={{ fontSize: "15px" }}
                        color={
                          open && modelName === "false_positive"
                            ? "primary"
                            : "inherit"
                        }
                        onClick={this.handleEditOpen.bind(
                          this,
                          "false_positive"
                        )}
                      >
                        <Edit fontSize="inherit" />
                      </IconButton>
                    </div>
                    <div className="clearfix" />
                    <div style={{ display: "flex" }}>
                      <Typography
                        style={{ display: "flex", alignItems: "center" }}
                      >
                        No
                      </Typography>
                      {open && modelName === "false_positive" ? (
                        <Field
                          component={SwitchField}
                          name="false_positive"
                          type='checkbox'
                          containerstyle={{ margin: "0 -15px 0 11px" }}
                          onChange={this.handleSubmitField.bind(this)}
                        />
                      ) : (
                        <Switch
                          disabled
                          defaultChecked={risk.false_positive}
                          classes={{
                            thumb: classes.thumb,
                            track: classes.switch_track,
                            switchBase: classes.switch_base,
                          }}
                        />
                      )}
                      <Typography
                        style={{ display: "flex", alignItems: "center" }}
                      >
                        Yes
                      </Typography>
                    </div>
                  </div>
                </Grid>
                <Grid item={true} xs={4}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Risk Adjusted")}
                    </Typography>
                    <Tooltip
                      title={t(
                        "Identifies that mitigating factors were identified or implemented, reducing the likelihood or impact of the risk."
                      )}
                    >
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                    <IconButton
                      size="small"
                      style={{ fontSize: "15px" }}
                      color={
                        open && modelName === "risk_adjusted"
                          ? "primary"
                          : "inherit"
                      }
                      onClick={this.handleEditOpen.bind(this, "risk_adjusted")}
                    >
                      <Edit fontSize="inherit" />
                    </IconButton>
                  </div>
                  <div className="clearfix" />
                  <div style={{ display: "flex" }}>
                    <Typography
                      style={{ display: "flex", alignItems: "center" }}
                    >
                      No
                    </Typography>
                    {open && modelName === "risk_adjusted" ? (
                      <Field
                        component={SwitchField}
                        name="risk_adjusted"
                        type='checkbox'
                        containerstyle={{ margin: "0 -15px 0 11px" }}
                        onChange={this.handleSubmitField.bind(this)}
                      />
                    ) : (
                      <Switch
                        disabled
                        defaultChecked={risk.risk_adjusted}
                        classes={{
                          thumb: classes.thumb,
                          track: classes.switch_track,
                          switchBase: classes.switch_base,
                        }}
                      />
                    )}
                    <Typography
                      style={{ display: "flex", alignItems: "center" }}
                    >
                      Yes
                    </Typography>
                  </div>
                </Grid>
                <Grid item={true} xs={12}>
                  {enableJustification.length > 0 
                  ? this.renderJustification() 
                  : <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t("Justification")}
                    </Typography>
                    <Tooltip
                      title={t(
                        "Justification"
                      )}
                    >
                      <Information
                        style={{ marginLeft: "5px" }}
                        fontSize="inherit"
                        color="disabled"
                      />
                    </Tooltip>
                  </div>
                  }               
                </Grid>
                <Grid item={true} xs={12}>
                  <CyioCoreObjectLabelsView
                    labels={risk.labels}
                    marginTop={5}
                    id={risk.id}
                    refreshQuery={refreshQuery}
                    typename={risk.__typename}
                  />
                </Grid>
              </Grid>
            </Form>
          </Formik>
        </Paper>
      </div>
    );
  }
}

RiskOverviewComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const RiskOverview = createFragmentContainer(
  RiskOverviewComponent,
  {
    risk: graphql`
      fragment RiskOverview_risk on Risk {
        __typename
        id
        created
        modified
        description
        risk_level
        priority
        false_positive
        risk_adjusted
        accepted
        justification
        vendor_dependency
        impacted_control_id
        first_seen
        last_seen
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
      }
    `,
  },
);

export default R.compose(inject18n, withStyles(styles))(RiskOverview);
