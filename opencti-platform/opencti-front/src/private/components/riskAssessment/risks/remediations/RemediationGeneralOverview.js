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
import PersonIcon from '@material-ui/icons/Person';
import LayersIcon from '@material-ui/icons/Layers';
import BuildIcon from '@material-ui/icons/Build';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
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
  avatarIcon: {
    width: '35px',
    height: '35px',
    color: 'white',
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
    const remediationOriginData = R.pipe(
      R.pathOr([], ['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(remediation);
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
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
                {remediationOriginData.actor_type === 'assessment_platform'
                    && <LayersIcon className={classes.avatarIcon} />}
                  {remediationOriginData.actor_type === 'tool'
                    && <BuildIcon className={classes.avatarIcon} />}
                  {remediationOriginData.actor_type === 'party'
                    && <PersonIcon className={classes.avatarIcon} />}
                  <div style={{ marginLeft: '20px' }}>
                    <Typography variant="subtitle1">
                      {remediationOriginData.actor_ref?.name
                        && t(remediationOriginData.actor_ref?.name)}
                    </Typography>
                    <Typography color="textSecondary" variant="disabled">
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
                    <Markdown
                      remarkPlugins={[remarkGfm, remarkParse]}
                      parserOptions={{ commonmark: true }}
                      className="markdown"
                    >
                      {remediation.description && t(remediation.description)}
                    </Markdown>
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
            actor_ref {
              ... on AssessmentPlatform {
                id
                name
              }
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
