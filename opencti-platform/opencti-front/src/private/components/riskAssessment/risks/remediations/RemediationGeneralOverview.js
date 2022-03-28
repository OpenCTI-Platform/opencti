import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose, propOr, map } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../../components/i18n';
import ItemAuthor from '../../../../../components/ItemAuthor';
import ItemMarking from '../../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../../components/ExpandableMarkdown';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '45px 35px 42px 35px',
    borderRadius: 6,
    position: 'relative',
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    textAlign: 'left',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '95%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '223px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  container: {
    display: 'flex',
  },
  fixed: {
    width: '200px',
  },
  flexItem: {
    flexGrow: '1',
    marginTop: '20px',
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
});

class RemediationGeneralOverviewComponent extends Component {
  render() {
    const {
      t,
      fd,
      fldt,
      classes,
      remediation,
      risk,
    } = this.props;
    console.log('remediationGenreal', remediation);
    const remediationOriginData = R.pathOr([], ['origins', 0, 'origin_actors', 0, 'actor'], remediation);
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        {/*  <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {remediation.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              remediation.objectMarking.edges,
            )
          ) : (
            <ItemMarking label="TLP:WHITE" />
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fldt(remediation.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(remediation.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', remediation)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={remediation.description}
            limit={250}
          />
        </Paper> */}
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={3}>
              <div style={{ marginBottom: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Name')}
                </Typography>
                <div className="clearfix" />
                {/* {t('Lorem Ipsum Dolor Sit Amet')} */}
                {remediation.name && t(remediation.name)}
              </div>
              <div style={{ marginBottom: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Created')}
                </Typography>
                <div className="clearfix" />
                {/* {t('Lorem Ipsum Dolor Sit Amet')} */}
                {remediation.created && fd(remediation.created)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Source')}
                </Typography>
                <div className="clearfix" />
                <div style={{ display: 'flex' }}>
                  <Badge
                    overlap="circular"
                    anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                    badgeContent={
                      <Avatar style={{ width: 15, height: 15, backgroundColor: 'green' }} alt="Remy Sharp" />
                    }
                  >
                    <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                  </Badge>
                  <div style={{ marginLeft: '20px' }}>
                    <Typography variant="subtitle1">
                      {remediationOriginData.name && t(remediationOriginData.name)}
                    </Typography>
                    <Typography color="textSecondary" variant="disabled">
                      {t('Lorem Ipsum Dolor Ist')}
                    </Typography>
                  </div>
                </div>
              </div>
              <div className={classes.container}>
                <div className={classes.fixed} style={{ marginTop: '20px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ marginTop: 5 }}
                  >
                    {t('Response Type')}
                  </Typography>
                  <div className="clearfix" />
                  <Button
                    variant="outlined"
                    size="small"
                    className={classes.statusButton}
                  >
                    {remediation.response_type && t(remediation.response_type)}
                  </Button>
                </div>
                <div className={classes.flexItem}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ marginTop: 5 }}
                  >
                    {t('Lifecycle')}
                  </Typography>
                  <div className="clearfix" />
                  <Button
                    variant="outlined"
                    size="small"
                    className={classes.statusButton}
                  >
                    {remediation.lifecycle && t(remediation.lifecycle)}
                  </Button>
                </div>
              </div>
            </Grid>
            <Grid item={true} xs={3}>
              <div style={{ marginBottom: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('ID')}
                </Typography>
                <div className="clearfix" />
                {remediation.id && t(remediation.id)}
              </div>
              <div style={{ marginBottom: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Modified')}
                </Typography>
                <div className="clearfix" />
                {/* {t('June 11 2021')} */}
                {remediation.modified && fd(remediation.modified)}
              </div>
            </Grid>
            <Grid xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Description')}
              </Typography>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {remediation.description && t(remediation.description)}
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RemediationGeneralOverviewComponent.propTypes = {
  remediation: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  risk: PropTypes.risk,
};

const RemediationGeneralOverview = createFragmentContainer(
  RemediationGeneralOverviewComponent,
  {
    remediation: graphql`
      fragment RemediationGeneralOverview_remediation on RiskResponse {
        id
        name                # Title
        description         # Description
        created             # Created
        modified            # Last Modified
        lifecycle           # Lifecycle
        response_type       # Response Type
        origins{            # Detection Source
          id
          origin_actors {
            actor_type
            actor {
              ... on Component {
                id
                component_type
                name          # Source
              }
              ... on OscalParty {
                id
                party_type
                name            # Source
              }
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RemediationGeneralOverview);
