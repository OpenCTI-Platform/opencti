import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import {
  Card,
  Typography,
  Grid,
  Checkbox,
} from '@material-ui/core';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import IconButton from '@material-ui/core/IconButton';
import Avatar from '@material-ui/core/Avatar';
import { StarBorderOutlined } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import {
  addBookmark,
  deleteBookMark,
} from '../../common/stix_domain_objects/StixDomainObjectBookmark';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';

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
});

class RiskCardComponent extends Component {
  render() {
    const {
      t,
      fsd,
      classes,
      node,
      selectAll,
      onToggleEntity,
      bookmarksIds,
      onLabelClick,
      selectedElements,
    } = this.props;
    console.log('RiskCardnode', node);
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <Card classes={{ root: classes.card }} raised={true} elevation={3}>
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          style= {{ background: (selectAll || node.id in (selectedElements || {})) && '#075AD3' } }
          to={`/dashboard/risk-assessment/risks/${node.id}`}
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
            <Grid item={true} className={classes.header}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('ID')}
                </Typography>
                {node.id && t(node.id)}
              </div>
              {/* <div style={{ marginRight: 'auto', marginLeft: '12px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Name')}
                </Typography>
                <Typography>
                  {node.name && t(node.name)}
                </Typography>
              </div> */}
              <div>
                <Checkbox
                  disableRipple={true}
                  onClick={onToggleEntity.bind(this, node)}
                  checked={selectAll || node.id in (selectedElements || {})}
                  color='primary'
                />
              </div>
            </Grid>
            <Grid container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom ={true}>
                  {t('Priority')}
                </Typography>
                <Typography>
                  {/* {node.priority && t(node.priority)} */}
                  {t('Priority')}
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom ={true}>
                  {t('Risk')}
                </Typography>
                <Typography>
                  {t('Medium')}
                  {node.risk && t(node.risk)}
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
                  {t('Component')}
                </Typography>
                <Typography>
                  {t('Lorem Ipsum')}
                  {/* {node.fqdn && truncate(t(node.fqdn), 25)} */}
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
                  {t('Lorem Ipsum')}
                  {/* {node.network_id && t(node.network_id)} */}
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
                  {t('Lorem Ipsum')}
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
                  {t('Lorem Ipsum')}
                  {/* {node.network_id && t(node.network_id)} */}
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
                  {t('Lorem Ipsum')}
                  {/* {node.fqdn && truncate(t(node.fqdn), 25)} */}
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
                  {t('Lorem Ipsum')}
                  {/* {node.network_id && t(node.network_id)} */}
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
      fragment RiskCard_node on POAMItem {
        id
        poam_id
        name
        occurrences
        related_risks {
          edges {
            node {
              risk_status
              deadline
              # characterizations {
              #   ... on RiskCharacterization {
              #     id
              #     risk
              #   }
              # }
              remediations {
                response_type
                lifecycle
              }
            }
          }
        }
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
