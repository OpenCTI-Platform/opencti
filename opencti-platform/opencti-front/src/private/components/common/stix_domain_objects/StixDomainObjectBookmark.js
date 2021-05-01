import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Avatar from '@material-ui/core/Avatar';
import { Public, StarBorderOutlined } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { commitMutation } from '../../../../relay/environment';
import { deleteNode, insertNode } from '../../../../utils/Store';
import ItemIcon from '../../../../components/ItemIcon';

const stixDomainObjectBookmarkCreateMutation = graphql`
  mutation StixDomainObjectBookmarkreateMutation($id: ID!, $type: String!) {
    bookmarkAdd(id: $id, type: $type) {
      id
      ...StixDomainObjectBookmark_node
    }
  }
`;

const stixDomainObjectBookmarkRemoveMutation = graphql`
  mutation StixDomainObjectBookmarkRemoveMutation($id: ID!) {
    bookmarkDelete(id: $id)
  }
`;

export const addBookmark = (id, type, event = null) => {
  if (event) {
    event.stopPropagation();
    event.preventDefault();
  }
  commitMutation({
    mutation: stixDomainObjectBookmarkCreateMutation,
    variables: { id, type },
    updater: (store) => insertNode(
      store,
      'Pagination_bookmarks',
      { types: [type] },
      'bookmarkAdd',
    ),
  });
};

export const deleteBookMark = (id, type, event = null) => {
  if (event) {
    event.stopPropagation();
    event.preventDefault();
  }
  commitMutation({
    mutation: stixDomainObjectBookmarkRemoveMutation,
    variables: { id },
    updater: (store) => deleteNode(store, 'Pagination_bookmarks', { types: [type] }, id),
  });
};

const styles = (theme) => ({
  card: {
    width: '100%',
    height: 70,
    borderRadius: 6,
  },
  cardDummy: {
    width: '100%',
    height: 70,
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
    height: 70,
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

class StixDomainObjectBookmarkComponent extends Component {
  render() {
    const {
      t, fsd, classes, node,
    } = this.props;
    const link = resolveLink(node.entity_type);
    return (
      <Card classes={{ root: classes.card }} raised={true}>
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`${link}/${node.id}`}
        >
          <CardHeader
            classes={{ root: classes.header }}
            avatar={
              <Avatar className={classes.avatar}>
                <ItemIcon type={node.entity_type} />
              </Avatar>
            }
            title={node.name}
            subheader={`${t('Updated the')} ${fsd(node.modified)}`}
            action={
              <IconButton
                size="small"
                onClick={deleteBookMark.bind(this, node.id, node.entity_type)}
                color="secondary"
                style={{ marginTop: 10 }}
              >
                <StarBorderOutlined />
              </IconButton>
            }
          />
        </CardActionArea>
      </Card>
    );
  }
}

StixDomainObjectBookmarkComponent.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const StixDomainObjectBookmarkFragment = createFragmentContainer(
  StixDomainObjectBookmarkComponent,
  {
    node: graphql`
      fragment StixDomainObjectBookmark_node on StixDomainObject {
        id
        entity_type
        parent_types
        created_at
        updated_at
        modified
        ... on AttackPattern {
          name
          x_mitre_id
        }
        ... on Campaign {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on Individual {
          name
        }
        ... on Organization {
          name
        }
        ... on Sector {
          name
        }
        ... on Indicator {
          name
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
        }
        ... on ThreatActor {
          name
        }
        ... on Tool {
          name
        }
        ... on Vulnerability {
          name
        }
        ... on Incident {
          name
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
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
        objectMarking {
          edges {
            node {
              id
              definition
              x_opencti_color
            }
          }
        }
      }
    `,
  },
);

export const StixDomainObjectBookmark = R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectBookmarkFragment);

class StixDomainObjectBookmarkDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.Dummy }} raised={true}>
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={<Avatar className={classes.avatarDisabled}>D</Avatar>}
            title={
              <div
                className={classes.placeholderHeader}
                style={{ width: '85%' }}
              />
            }
            titleTypographyProps={{ color: 'inherit' }}
            subheader={
              <div
                className={classes.placeholderHeaderDark}
                style={{ width: '70%' }}
              />
            }
            action={<Public className={classes.icon} />}
          />
          <CardContent classes={{ root: classes.contentDummy }}>
            <div className="fakeItem" style={{ width: '90%' }} />
            <div className="fakeItem" style={{ width: '95%' }} />
            <div className="fakeItem" style={{ width: '90%' }} />
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

StixDomainObjectBookmarkDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const StixDomainObjectBookmarkDummy = R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectBookmarkDummyComponent);
