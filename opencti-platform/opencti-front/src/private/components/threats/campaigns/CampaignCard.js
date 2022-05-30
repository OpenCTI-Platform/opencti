import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import withStyles from '@mui/styles/withStyles';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Avatar from '@mui/material/Avatar';
import IconButton from '@mui/material/IconButton';
import { StarBorderOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import {
  addBookmark,
  deleteBookMark,
} from '../../common/stix_domain_objects/StixDomainObjectBookmark';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: 170,
    borderRadius: 6,
  },
  cardDummy: {
    width: '100%',
    height: 170,
    color: theme.palette.grey[700],
    borderRadius: 6,
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
    height: 55,
    paddingBottom: 0,
    marginBottom: 0,
  },
  content: {
    width: '100%',
    paddingTop: 0,
  },
  description: {
    height: 61,
    display: '-webkit-box',
    '-webkit-box-orient': 'vertical',
    '-webkit-line-clamp': 2,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 15,
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

class CampaignCardComponent extends Component {
  render() {
    const { t, fsd, classes, node, bookmarksIds, onLabelClick } = this.props;
    return (
      <Card classes={{ root: classes.card }} variant="outlined">
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`/dashboard/threats/campaigns/${node.id}`}
        >
          <CardHeader
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
                    ? deleteBookMark.bind(this, node.id, 'Campaign')
                    : addBookmark.bind(this, node.id, 'Campaign')
                }
                color={bookmarksIds.includes(node.id) ? 'secondary' : 'primary'}
              >
                <StarBorderOutlined />
              </IconButton>
            }
          />
          <CardContent className={classes.content}>
            <div className={classes.description}>
              <Markdown
                remarkPlugins={[remarkGfm, remarkParse]}
                parserOptions={{ commonmark: true }}
                disallowedTypes={['link', 'linkReference']}
                unwrapDisallowed={true}
              >
                {node.description}
              </Markdown>
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

CampaignCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const CampaignCardFragment = createFragmentContainer(CampaignCardComponent, {
  node: graphql`
    fragment CampaignCard_node on Campaign {
      id
      name
      description
      created
      modified
      objectMarking {
        edges {
          node {
            id
            definition
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
    }
  `,
});

export const CampaignCard = compose(
  inject18n,
  withStyles(styles),
)(CampaignCardFragment);

class CampaignCardDummyComponent extends Component {
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
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="95%"
              style={{ marginBottom: 10 }}
            />
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

CampaignCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const CampaignCardDummy = compose(
  inject18n,
  withStyles(styles),
)(CampaignCardDummyComponent);
