import { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import CardHeader from '@mui/material/CardHeader';
import { useTheme } from '@mui/styles';
import CardContent from '@mui/material/CardContent';
import Skeleton from '@mui/material/Skeleton';
import Card from '@common/card/Card';
import inject18n, { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { renderCardTitle } from '../../../../utils/Card';
import BookmarkToggle from '../../../../components/common/bookmark/BookmarkToggle';

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

const StixDomainObjectBookmarkComponent = ({ node }) => {
  const { t_i18n, fld } = useFormatter();
  const theme = useTheme();
  const link = resolveLink(node.entity_type);

  return (
    <Card to={`${link}/${node.id}`}>
      <CardHeader
        title={renderCardTitle(node)}
        subheader={t_i18n(
          'Last modified on',
          { values: { date: fld(node.modified) } },
        )}
        sx={{
          padding: 0,
          mb: 2,
          '.MuiCardHeader-content': {
            minWidth: 0,
          },
          '.MuiCardHeader-title': {
            mt: 0,
          },
          '.MuiCardHeader-subheader': {
            fontSize: 12,
            color: theme.palette.text.secondary,
          },
        }}
        action={(
          <BookmarkToggle
            stixId={node.id}
            stixEntityType={node.entity_type}
            isBookmarked={true}
          />
        )}
      />
    </Card>
  );
};

StixDomainObjectBookmarkComponent.propTypes = {
  node: PropTypes.object,
};

export const StixDomainObjectBookmark = createFragmentContainer(
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
