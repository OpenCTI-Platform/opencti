import { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { StarBorderOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Skeleton from '@mui/material/Skeleton';
import withTheme from '@mui/styles/withTheme';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { commitMutation } from '../../../../relay/environment';
import { deleteNode, insertNode } from '../../../../utils/store';
import { renderCardTitle } from '../../../../utils/Card';

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
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  area: {
    width: '100%',
    height: '100%',
  },
  header: {
    height: 55,
    padding: 0,
    marginBottom: 0,
  },
  contentDummy: {
    width: '100%',
    height: 120,
    overflow: 'hidden',
    marginTop: 15,
  },
});

class StixDomainObjectBookmarkComponent extends Component {
  render() {
    const { t, fsd, classes, node } = this.props;
    const link = resolveLink(node.entity_type);
    return (
      <Card to={`${link}/${node.id}`}>
        <CardHeader
          classes={{ root: classes.header }}
          title={renderCardTitle(node)}
          subheader={`${t('Updated on')} ${fsd(node.modified)}`}
          action={(
            <IconButton
              size="small"
              onClick={deleteBookMark.bind(this, node.id, node.entity_type)}
              color="secondary"
            >
              <StarBorderOutlined />
            </IconButton>
          )}
        />
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
        ... on System {
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
          countryFlag: stixCoreRelationships(
            relationship_type: "originates-from"
            toTypes: ["Country"]
            first: 1
            orderBy: created_at
            orderMode: desc
          ) {
            edges {
              node {
                to {
                  ... on Country {
                    name
                    x_opencti_aliases
                  }
                }
              }
            }
          }
          avatar {
            id
            name
          }
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on AdministrativeArea {
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
          ... on ThreatActorIndividual {
            countryFlag: stixCoreRelationships(
              relationship_type: "located-at"
              toTypes: ["Country"]
              first: 1
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                      x_opencti_aliases
                    }
                  }
                }
              }
            }
            avatar {
              id
              name
            }
          }
          ... on ThreatActorGroup {
            countryFlag: stixCoreRelationships(
              relationship_type: "located-at"
              toTypes: ["Country"]
              first: 1
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                      x_opencti_aliases
                    }
                  }
                }
              }
            }
            avatar {
              id
              name
            }
          }

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
          id
          value
          color
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    `,
  },
);

export const StixDomainObjectBookmark = R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixDomainObjectBookmarkFragment);

class StixDomainObjectBookmarkDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card>
        <CardHeader
          classes={{ root: classes.header }}
          avatar={(
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          )}
          title={(
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          )}
          subheader={(
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          )}
          action={(
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          )}
          slotProps={{
            title: { color: 'inherit' },
          }}
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
