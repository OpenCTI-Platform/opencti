import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import {
  compose,
  pipe,
  pathOr,
  mergeAll,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import {
  Card,
  Typography,
  Grid,
  Checkbox,
  Button,
} from '@material-ui/core';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import RiskAssessmentPopover from './RiskAssessmentPopover';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
  },
  cardDummy: {
    width: '100%',
    height: '319px',
    color: theme.palette.grey[700],
    borderRadius: 9,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    backgroundColor: theme.palette.grey[600],
  },
  area: {
    width: '100%',
    height: '100%',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: '13px',
  },
  headerDummy: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  content: {
    width: '100%',
    padding: '24px',
  },
  description: {
    height: 170,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 7,
  },
  contentDummy: {
    width: '100%',
    height: 120,
    overflow: 'hidden',
    marginTop: 15,
  },
  placeholderHeader: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.grey[700],
  },
  placeholderHeaderDark: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.grey[800],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  buttonRipple: {
    opacity: 0,
  },
});

const colors = {
  very_high: {
    bg: 'rgba(243, 84, 38, 0.2)',
    stroke: '#F35426',
  },
  high: {
    bg: 'rgba(249, 180, 6, 0.2)',
    stroke: '#F9B406',
  },
  moderate: {
    bg: 'rgba(252, 218, 130, 0.2)',
    stroke: '#FCDA82',
  },
  low: {
    bg: 'rgba(254, 236, 193, 0.2)',
    stroke: '#FEECC1',
  },
  very_low: {
    bg: 'rgba(241, 241, 242, 0.25)',
    stroke: '#F1F1F2',
  },
  unknown: {
    bg: '#075AD333',
    stroke: '#075AD3',
  },
};

class RiskCardComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openMenu: false,
    };
  }

  handleOpenMenu(isOpen) {
    this.setState({ openMenu: isOpen });
  }

  render() {
    const {
      t,
      classes,
      node,
      history,
      selectAll,
      onToggleEntity,
      selectedElements,
    } = this.props;
    const riskData = pipe(
      pathOr([]),
      mergeAll,
    )(node);
    const riskRemediation = pipe(
      pathOr([], ['remediations']),
      mergeAll,
    )(node);
    return (
      <Card classes={{ root: classes.card }} raised={true} elevation={3}>
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          style={{ background: (selectAll || node.id in (selectedElements || {})) && '#075AD3' }}
          TouchRippleProps={ this.state.openMenu && { classes: { root: classes.buttonRipple } }}
          to={`/activities/risk assessment/risks/${node?.id}`}
        >
          {/* <CardHeader
            classes={{ root: classes.header }}
            avatar={
              <Avatar className={classes.avatar}>{node.name.charAt(0)}</Avatar>
            }
            title={node.name}
            subheader={`${t('Updated the')} ${fsd(node.modified)}`}
            action={
              <IconButton
                size="small"
                onClick={
                  bookmarksIds.includes(node.id)
                    ? deleteBookMark.bind(this, node.id, 'Threat-Actor')
                    : addBookmark.bind(this, node.id, 'Threat-Actor')
                }
                color={bookmarksIds.includes(node.id) ? 'secondary' : 'primary'}
                style={{ marginTop: 10 }}
              >
                <StarBorderOutlined />
              </IconButton>
            }
          /> */}
          <CardContent className={classes.content}>
            <Grid
              item={true}
              className={classes.header}
            >
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Name')}
                </Typography>
                {node.name && t(node.name)}
              </div>
              <Grid
                item={true}
                onClick={(event) => event.preventDefault()}
                style={{ display: 'flex' }}
              >
                <RiskAssessmentPopover
                  handleOpenMenu={this.handleOpenMenu.bind(this)}
                  history={history}
                  nodeId={node?.id}
                  riskNode={riskData.node}
                  node={node}
                />
                <Checkbox
                  disableRipple={true}
                  onClick={onToggleEntity.bind(this, node)}
                  checked={selectAll || node.id in (selectedElements || {})}
                  color='primary'
                />
              </Grid>
            </Grid>
            <Grid container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}>
                  {t('Priority')}
                </Typography>
                <Typography>
                  {node.priority && t(node.priority)}
                  {/* {t('Priority')} */}
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}>
                  {t('Risk')}
                </Typography>
                <Button
                  variant="outlined"
                  color="default"
                  size="small"
                  style={{ backgroundColor: colors[node?.risk_level].bg, borderColor: colors[node?.risk_level].stroke, borderRadius: '4px' }}
                >
                  {node?.risk_level && node?.risk_level}
                </Button>
                {/* <Typography>
                  {node?.risk_level && node?.risk_level}
                </Typography> */}
              </Grid>
            </Grid>
            <Grid container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Component')}
                </Typography>
                <Typography>
                  {node.fqdn && truncate(t(node.fqdn), 25)}
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Controls')}
                </Typography>
                <Typography>
                  {node.network_id && t(node.network_id)}
                </Typography>
              </Grid>
            </Grid>
            <Grid container={true}>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Component')}
                </Typography>
                <Typography>
                  {node.component_type && t(node.component_type)}
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Controls')}
                </Typography>
                <Typography>
                  {node.network_id && t(node.network_id)}
                </Typography>
              </Grid>
            </Grid>
            <Grid container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Response')}
                </Typography>
                <Typography>
                  {riskRemediation.response_type && t(riskRemediation.response_type)}
                </Typography>
              </Grid>
              <Grid xs={6} item={true} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Lifecycle')}
                </Typography>
                <Typography>
                  {riskRemediation.lifecycle && t(riskRemediation.lifecycle)}
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

RiskCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
  onBookmarkClick: PropTypes.func,
};

const RiskCardFragment = createFragmentContainer(
  RiskCardComponent,
  {
    node: graphql`
      fragment RiskCard_node on Risk {
        id
        poam_id
        name
        risk_level
        risk_status
        response_type
        lifecycle
        occurrences
        deadline
      }
    `,
  },
);

export const RiskCard = compose(
  inject18n,
  withStyles(styles),
)(RiskCardFragment);

class RiskCardDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.cardDummy }} raised={true} elevation={3}>
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            title={
              <div className={classes.headerDummy}>
                <Skeleton
                  animation="wave"
                  variant="circle"
                  width={30}
                  height={30}
                />
                <div style={{ width: '100%', padding: '0px 20px' }}>
                  <Skeleton
                    animation="wave"
                    variant="rect"
                    width="100%"
                    style={{ marginBottom: 10 }}
                  />
                  <Skeleton
                    animation="wave"
                    variant="rect"
                    width="100%"
                  />
                </div>
                <Skeleton
                  animation="wave"
                  variant="circle"
                  width={30}
                  height={30}
                />
              </div>
            }
            titleTypographyProps={{ color: 'inherit' }}
          />
          <CardContent classes={{ root: classes.contentDummy }}>
            <Skeleton
              animation="wave"
              variant="rect"
              width="90%"
              style={{ marginBottom: 10 }}
            />
            <Skeleton
              animation="wave"
              variant="rect"
              width="95%"
              style={{ marginBottom: 10 }}
            />
            <Skeleton
              animation="wave"
              variant="rect"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

RiskCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const RiskCardDummy = compose(
  inject18n,
  withStyles(styles),
)(RiskCardDummyComponent);
