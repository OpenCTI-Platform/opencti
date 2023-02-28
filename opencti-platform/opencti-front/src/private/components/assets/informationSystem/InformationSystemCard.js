import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Checkbox from '@material-ui/core/Checkbox';
import CheckIcon from '@material-ui/icons/Check';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectLabels from '../../common/stix_core_objects/CyioCoreObjectLabels';
import RiskLevel from '../../common/form/RiskLevel';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
    border: `1.5px solid ${theme.palette.dataView.border}`,
  },
  selectedItem: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
    border: `1.5px solid ${theme.palette.dataView.selectedBorder}`,
    background: theme.palette.dataView.selectedBackgroundColor,
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
  icon: {
    margin: '10px 20px 0 0',
    fontSize: 40,
    color: '#242d30',
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
  body: {
    marginBottom: '13px',
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
});

class InformationSystemCardComponent extends Component {
  render() {
    const {
      t,
      fsd,
      node,
      classes,
      selectAll,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <Card
        classes={{
          root: (selectAll || node.id in (selectedElements || {}))
            ? classes.selectedItem : classes.card,
        }}
        raised={true}
        elevation={3}
      >
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`/defender_hq/assets/information_systems/${node.id}`}
          data-cy='information_systems card'
        >
          <CardContent className={classes.content}>
            <Grid item={true} className={classes.header}>
              <div style={{ marginRight: 'auto', marginLeft: '12px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Name')}
                </Typography>
                <div className="clearfix" />
                <Typography>
                  {/* {t('KK-HWELL-011')} */}
                  {node.system_name && t(node.system_name)}
                </Typography>
              </div>
              <div>
                <Checkbox
                  color='primary'
                  onClick={onToggleEntity.bind(this, node)}
                  checked={selectAll || node.id in (selectedElements || {})}
                  disableRipple={true}
                />
              </div>
            </Grid>
            <Grid xs={12} container={true} >
              <Grid item={true} xs={7} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Severity')}
                </Typography>
                <Typography>
                  {node?.risk_level && <RiskLevel
                    risk={node?.top_risk_severity}
                  />}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}>
                  {t('Sensitivity Level')}
                </Typography>
                <Typography>
                  {/* {t('KK-HWELL-011')} */}
                  {node?.security_sensitivity_level && <RiskLevel
                    risk={node?.security_sensitivity_level}
                  />}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Status')}
                </Typography>
                <Typography>
                  {node.operational_status && node.operational_status}
                </Typography>
                <div className="clearfix" />
              </Grid>
              <Grid xs={5} item={true} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}>
                  {t('Critical System')}
                </Typography>
                <Typography>
                  {node.critical_system_designation && <CheckIcon />}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}>
                  {t('Privacy Sensitivity')}
                </Typography>
                <Typography>
                  {node.privacy_designation && <CheckIcon />}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Risks')}
                </Typography>
                <Typography>
                  {node.risk_count && node.risk_count}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Date Created')}
                </Typography>
                <Typography>
                  {node.created && fsd(node.created)}
                </Typography>
              </Grid>
            </Grid>
            <div className={classes.objectLabel}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}>
                {t('Label')}
              </Typography>
              <CyioCoreObjectLabels
                labels={node.labels}
                onClick={onLabelClick.bind(this)}
              />
            </div>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

InformationSystemCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const InformationSystemCardFragment = createFragmentContainer(
  InformationSystemCardComponent,
  {
    node: graphql`
      fragment InformationSystemCard_node on InformationSystem {
        id
        short_name
        system_name
        critical_system_designation
        security_sensitivity_level
        privacy_designation
        operational_status
        created
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

export const InformationSystemCard = compose(
  inject18n,
  withStyles(styles),
)(InformationSystemCardFragment);

class InformationSystemDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.cardDummy }} raised={true} elevation={3}>
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={
              <Skeleton
                animation="wave"
                variant="circle"
                width={30}
                height={30}
              />
            }
            title={
              <Skeleton
                animation="wave"
                variant="rect"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            }
            titleTypographyProps={{ color: 'inherit' }}
            subheader={
              <Skeleton
                animation="wave"
                variant="rect"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            }
            action={
              <Skeleton
                animation="wave"
                variant="circle"
                width={30}
                height={30}
              />
            }
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

InformationSystemDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const InformationSystemCardDummy = compose(
  inject18n,
  withStyles(styles),
)(InformationSystemDummyComponent);
