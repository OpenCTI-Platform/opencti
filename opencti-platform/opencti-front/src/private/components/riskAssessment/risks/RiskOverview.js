import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr, map } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
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
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
});

class RiskOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk,
    } = this.props;
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        {/*  <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {risk.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              risk.objectMarking.edges,
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
          {fldt(risk.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(risk.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', risk)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={risk.description}
            limit={250}
          />
        </Paper> */}
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('ID')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'ID',
                  )}
                >
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
                style={{ float: 'left' }}
              >
                {t('Items ID')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'Items ID',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {risk.id && t(risk.id)}
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid style={{ marginTop: '10px' }} item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Description')}
              </Typography>
              <div style={{ float: 'left', marginLeft: '5px' }}>
                <Tooltip
                  title={t(
                    'Description',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {risk.description && t(risk.description)}
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '58px', marginTop: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Weakness')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Weakness',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t('Lorem Ipsum')}
                {/* {risk.weakness && t(risk.weakness)} */}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: '10px' }}
                >
                  {t('Risk Rating')}
                </Typography>
                <div style={{ float: 'left', margin: '11px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Risk Rating',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t('Lorem Ipsum')}
              </div>
              <div style={{ marginTop: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Impact')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Version',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t('2.0')}
                {/* {risk.impact && t(risk.impact)} */}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Responsible Parties')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Responsible Parties',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
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
                      {t('Lorem Ipsum')}
                    </Typography>
                    <Typography color="textSecondary" variant="disabled">
                      {t('Lorem Ipsum Dolor Ist')}
                    </Typography>
                  </div>
                </div>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div style={{ marginTop: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Controls')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Controls',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Chip key={risk.id} classes={{ root: classes.chip }} label={t('Lorem Ipsum Dono Ist Sei')} color="primary" />
                <Chip key={risk.id} classes={{ root: classes.chip }} label={t('Lorem Ipsum Dono Ist Sei')} color="primary" />
                {/* <ItemCreator creator={risk.creator} /> */}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Priority')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Priority',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                 {risk.priority && t(risk.priority)}
              </div>
              <div style={{ marginBottom: '40px', marginTop: '25px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Likelihood')}
                </Typography>
                <div style={{ float: 'left', marginLeft: '5px' }}>
                  <Tooltip
                    title={t(
                      'Likelihood',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t('June 11, 2021')}
              </div>
              <div style={{ display: 'flex', marginTop: '15px' }}>
                <Badge
                  overlap="circular"
                  anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                  badgeContent={
                    <Avatar style={{ width: 15, height: 15, backgroundColor: 'green' }} alt="Remy Sharp" />
                  }
                >
                  <Avatar alt="AB" src="/static/images/avatar/2.jpg" />
                </Badge>
                <div style={{ marginLeft: '20px' }}>
                  <Typography variant="subtitle1">
                    {t('Lorem Ipsum')}
                  </Typography>
                  <Typography variant="disabled" color="textSecondary">
                    {t('Lorem Ipsum Dolor Ist')}
                  </Typography>
                </div>
              </div>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid style={{ marginTop: '20px' }} item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Label')}
              </Typography>
              <div style={{ float: 'left', margin: '0 0 0 5px' }}>
                <Tooltip
                  title={t(
                    'Label',
                  )}
                >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <StixCoreObjectLabels
                labels={objectLabel}
                marginTop={20}
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
};

const RiskOverview = createFragmentContainer(
  RiskOverviewComponent,
  {
    risk: graphql`
      fragment RiskOverview_risk on Risk {
        id
        description
        characterizations {
          edges {
            node {
              ... on RiskCharacterization {
                impact
                likelihood
              }
            }
          }
        }
        impacted_control_id
        priority
        labels
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskOverview);
