import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import IconButton from '@mui/material/IconButton';
import { StarBorderOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import Typography from '@mui/material/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import {
  addBookmark,
  deleteBookMark,
} from '../../common/stix_domain_objects/StixDomainObjectBookmark';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import ItemIcon from '../../../../components/ItemIcon';
import { emptyFilled } from '../../../../utils/String';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: 320,
    borderRadius: 6,
  },
  cardDummy: {
    width: '100%',
    height: 320,
    color: theme.palette.grey[700],
    borderRadius: 6,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
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
    height: 55,
    paddingBottom: 0,
    marginBottom: 0,
  },
  content: {
    width: '100%',
    paddingTop: 0,
  },
  contentDummy: {
    width: '100%',
    height: 200,
    marginTop: 20,
  },
  description: {
    marginTop: 5,
    height: 65,
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 3,
    '-webkit-box-orient': 'vertical',
  },
  objectLabel: {
    height: 45,
    paddingTop: 15,
  },
  extras: {
    marginTop: 25,
  },
  extraColumn: {
    height: 45,
    width: '50%',
    float: 'left',
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 2,
    '-webkit-box-orient': 'vertical',
  },
  title: {
    fontWeight: 600,
  },
});

class IntrusionSetCardComponent extends Component {
  render() {
    const { t, fld, classes, node, bookmarksIds, onLabelClick } = this.props;
    const usedMalware = node.usedMalware.map((n) => n.entity.name).join(', ');
    const targetedCountries = node.targetedCountries
      .map((n) => n.entity.name)
      .join(', ');
    const targetedSectors = node.targetedSectors
      .map((n) => n.entity.name)
      .join(', ');
    return (
      <Card classes={{ root: classes.card }} variant="outlined">
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`/dashboard/threats/intrusion_sets/${node.id}`}
        >
          <CardHeader
            classes={{ root: classes.header, title: classes.title }}
            avatar={<ItemIcon type="Intrusion-Set" size="large" />}
            title={node.name}
            subheader={fld(node.modified)}
            action={
              <IconButton
                size="small"
                onClick={
                  bookmarksIds.includes(node.id)
                    ? deleteBookMark.bind(this, node.id, 'Intrusion-Set')
                    : addBookmark.bind(this, node.id, 'Intrusion-Set')
                }
                color={bookmarksIds.includes(node.id) ? 'secondary' : 'primary'}
              >
                <StarBorderOutlined />
              </IconButton>
            }
          />
          <CardContent className={classes.content}>
            <div className={classes.description}>
              <MarkdownDisplay
                content={node.description}
                remarkGfmPlugin={true}
                commonmark={true}
                removeLinks={true}
                limit={260}
              />
            </div>
            <div className={classes.extras}>
              <div className={classes.extraColumn} style={{ paddingRight: 10 }}>
                <Typography variant="h4">{t('Known as')}</Typography>
                <Typography variant="body2">
                  {emptyFilled((node.aliases || []).join(', '))}
                </Typography>
              </div>
              <div className={classes.extraColumn} style={{ paddingLeft: 10 }}>
                <Typography variant="h4">{t('Used malware')}</Typography>
                <Typography variant="body2">
                  {emptyFilled(usedMalware)}
                </Typography>
              </div>
              <div className="clearfix" />
            </div>
            <div className={classes.extras}>
              <div className={classes.extraColumn} style={{ paddingRight: 10 }}>
                <Typography variant="h4">{t('Targeted countries')}</Typography>
                <Typography variant="body2">
                  {emptyFilled(targetedCountries)}
                </Typography>
              </div>
              <div className={classes.extraColumn} style={{ paddingLeft: 10 }}>
                <Typography variant="h4">{t('Targeted sectors')}</Typography>
                <Typography variant="body2">
                  {emptyFilled(targetedSectors)}
                </Typography>
              </div>
              <div className="clearfix" />
            </div>
            <div className={classes.objectLabel}>
              <StixCoreObjectLabels
                labels={node.objectLabel}
                onClick={onLabelClick.bind(this)}
              />
            </div>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

IntrusionSetCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const IntrusionSetCardFragment = createFragmentContainer(
  IntrusionSetCardComponent,
  {
    node: graphql`
      fragment IntrusionSetCard_node on IntrusionSet {
        id
        name
        aliases
        description
        created
        modified
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        targetedCountries: stixCoreObjectsDistribution(
          operation: count
          field: "internal_id"
          relationship_type: ["targets"]
          types: ["Country"]
          limit: 5
        ) {
          label
          entity {
            ... on Country {
              name
            }
          }
        }
        targetedSectors: stixCoreObjectsDistribution(
          operation: count
          field: "internal_id"
          relationship_type: ["targets"]
          types: ["Sector"]
          limit: 5
        ) {
          label
          entity {
            ... on Sector {
              name
            }
          }
        }
        usedMalware: stixCoreObjectsDistribution(
          operation: count
          field: "internal_id"
          relationship_type: ["uses"]
          types: ["Malware"]
          limit: 5
        ) {
          label
          entity {
            ... on Malware {
              name
            }
          }
        }
      }
    `,
  },
);

export const IntrusionSetCard = compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetCardFragment);

class IntrusionSetCardDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.cardDummy }} variant="outlined">
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={
              <Skeleton
                animation="wave"
                variant="circular"
                width={30}
                height={30}
              />
            }
            title={
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            }
            titleTypographyProps={{ color: 'inherit' }}
            subheader={
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            }
            action={
              <Skeleton
                animation="wave"
                variant="circular"
                width={30}
                height={30}
              />
            }
          />
          <CardContent classes={{ root: classes.contentDummy }}>
            <div className={classes.description}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                style={{ marginBottom: 10 }}
              />
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="80%"
                style={{ marginBottom: 10 }}
              />
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            </div>
            <div className={classes.extras}>
              <div className={classes.extraColumn} style={{ paddingRight: 10 }}>
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="100%"
                  style={{ marginBottom: 10 }}
                />
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="100%"
                  style={{ marginBottom: 10 }}
                />
              </div>
              <div className={classes.extraColumn} style={{ paddingLeft: 10 }}>
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="100%"
                  style={{ marginBottom: 10 }}
                />
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="100%"
                  style={{ marginBottom: 10 }}
                />
              </div>
            </div>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

IntrusionSetCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const IntrusionSetCardDummy = compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetCardDummyComponent);
