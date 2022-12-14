/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectLabelsView from '../../common/stix_core_objects/CyioCoreObjectLabelsView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '50%',
    margin: '10px 0 0 0',
    padding: '24px 24px 0 24px',
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
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
});

class RiskOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk, refreshQuery,
    } = this.props;
    return (
      <div style={{ height: "100%" }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t("Basic Information")}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: "left" }}
              >
                {t("ID")}
              </Typography>
              <div style={{ float: "left", marginLeft: "5px" }}>
                <Tooltip title={t("Uniquely identifies this object")}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {risk.id && t(risk.id)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: "left" }}
              >
                {t("Created")}
              </Typography>
              <div style={{ float: "left", marginLeft: "5px" }}>
                <Tooltip
                  title={t(
                    "Indicates the date and time at which the object was originally created."
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {risk.created && fldt(risk.created)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: "left" }}
              >
                {t("Modified")}
              </Typography>
              <div style={{ float: "left", marginLeft: "5px" }}>
                <Tooltip
                  title={t(
                    "Indicates the date and time that this particular version of the object was last modified."
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {risk.modified && fldt(risk.modified)}
            </Grid>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: "left" }}
              >
                {t("Description")}
              </Typography>
              <div style={{ float: "left", marginLeft: "5px" }}>
                <Tooltip
                  title={t(
                    "Identifies a human-readable summary of the identified risk, to include a statement of how the risk impacts the system."
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
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
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: "10px" }}
                >
                  {t("Risk Rating")}
                </Typography>
                <div style={{ float: "left", margin: "11px 0 0 5px" }}>
                  <Tooltip title={t("Risk Rating")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.risk_level && t(risk.risk_level)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 10 }}
                >
                  {t("Priority")}
                </Typography>
                <div style={{ float: "left", margin: "11px 0 0 5px" }}>
                  <Tooltip
                    title={t(
                      "Identifies Assessor's recommended risk priority. Lower numbers are higher priority. One (1) is highest priority."
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.priority && t(risk.priority)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Impact")}
                </Typography>
                <div style={{ float: "left", marginLeft: "5px" }}>
                  <Tooltip title={t("Version")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* {risk.impact && t(risk.impact)} */}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Likelihood")}
                </Typography>
                <div style={{ float: "left", marginLeft: "5px" }}>
                  <Tooltip title={t("Likelihood")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* {risk.likelihood && t(risk.likelihood)} */}
              </div>
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
        created
        modified
        description
        risk_level
        priority
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
