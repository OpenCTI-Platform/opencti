import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Switch, Tooltip } from '@material-ui/core';
import Chip from '@material-ui/core/Chip';
import Button from '@material-ui/core/Button';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Link from '@material-ui/core/Link';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import Launch from '@material-ui/icons/Launch';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, Information } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../../components/ExpandableMarkdown';
import inject18n from '../../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  link: {
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
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

class RemediationGeneralDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      remediation,
      fd,
      history,
    } = this.props;
    const remediationOriginData = R.pathOr([], ['origins', 0, 'origin_actors', 0, 'actor'], remediation);
    // const relatedRisksEdges = R.pipe(
    //   R.pathOr([], ['related_risks', 'edges']),
    //   R.map((value) => ({
    //     name: value.node.name,
    //     description: value.node.description,
    //     statement: value.node.statement,
    //     risk_status: value.node.risk_status,
    //     deadline: value.node.deadline,
    //     false_positive: value.node.false_positive,
    //     risk_adjusted: value.node.risk_adjusted,
    //     vendor_dependency: value.node.vendor_dependency,
    //   })),
    // )(remediation);
    // const relatedObservationsEdges = R.pipe(
    //   R.pathOr([], ['related_observations', 'edges']),
    //   R.map((value) => ({
    //     impacted_component: value.node.impacted_component,
    //     impacted_asset: value.node.subjects,
    //   })),
    // )(remediation);
    // console.log('RiskDetailsMain', relatedObservationsEdges);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
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
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 5 }}
                >
                  {t('Response Type')}
                </Typography>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default', marginBottom: '5px' }}
                >
                  {remediation.response_type && t(remediation.response_type)}
                </Button>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div style={{ marginTop: '85px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 5 }}
                >
                  {t('Lifecycle')}
                </Typography>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default', marginBottom: '5px' }}
                >
                  {remediation.lifecycle && t(remediation.lifecycle)}
                </Button>
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RemediationGeneralDetailsComponent.propTypes = {
  remediation: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const RemediationGeneralDetails = createFragmentContainer(
  RemediationGeneralDetailsComponent,
  {
    remediation: graphql`
      fragment RemediationGeneralDetails_remediation on RiskResponse {
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

export default compose(inject18n, withStyles(styles))(RemediationGeneralDetails);
