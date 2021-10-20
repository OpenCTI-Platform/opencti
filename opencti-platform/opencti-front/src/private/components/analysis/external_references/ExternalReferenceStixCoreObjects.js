import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import List from '@material-ui/core/List';
import { Link } from 'react-router-dom';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class ExternalReferenceStixCoreObjectsComponent extends Component {
  render() {
    const {
      t, fd, classes, externalReference,
    } = this.props;
    const stixCoreObjects = R.map(
      (n) => n.node,
      externalReference.references.edges,
    );
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Linked objects')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List classes={{ root: classes.list }}>
            {stixCoreObjects.map((stixCoreObject) => (
              <ListItem
                key={stixCoreObject.id}
                classes={{ root: classes.menuItem }}
                divider={true}
                button={true}
                component={Link}
                to={`${resolveLink(stixCoreObject.entity_type)}/${
                  stixCoreObject.id
                }`}
              >
                <ListItemIcon>
                  <ItemIcon type={stixCoreObject.entity_type} />
                </ListItemIcon>
                <ListItemText
                  primary={`${
                    stixCoreObject.x_mitre_id
                      ? `[${stixCoreObject.x_mitre_id}] `
                      : ''
                  }${truncate(
                    stixCoreObject.name
                      || stixCoreObject.observable_value
                      || stixCoreObject.attribute_abstract
                      || stixCoreObject.content
                      || stixCoreObject.opinion
                      || `${fd(stixCoreObject.first_observed)} - ${fd(
                        stixCoreObject.last_observed,
                      )}`,
                    60,
                  )}`}
                  secondary={
                    <Markdown
                      remarkPlugins={[remarkGfm, remarkParse]}
                      parserOptions={{ commonmark: true }}
                      className="markdown"
                    >
                      {truncate(
                        stixCoreObject.description
                          || fd(stixCoreObject.created_at),
                        200,
                      )}
                    </Markdown>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      </div>
    );
  }
}

ExternalReferenceStixCoreObjectsComponent.propTypes = {
  externalReference: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ExternalReferenceStixCoreObjects = createFragmentContainer(
  ExternalReferenceStixCoreObjectsComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceStixCoreObjects_externalReference on ExternalReference {
        id
        references {
          edges {
            node {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on StixCoreObject {
                created_at
                createdBy {
                  ... on Identity {
                    id
                    name
                    entity_type
                  }
                }
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
                }
              }
              ... on StixDomainObject {
                is_inferred
                created
              }
              ... on AttackPattern {
                name
                x_mitre_id
              }
              ... on Campaign {
                name
                first_seen
                last_seen
              }
              ... on ObservedData {
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
                valid_from
              }
              ... on Infrastructure {
                name
              }
              ... on IntrusionSet {
                name
                first_seen
                last_seen
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
                first_seen
                last_seen
              }
              ... on ThreatActor {
                name
                first_seen
                last_seen
              }
              ... on Tool {
                name
              }
              ... on Vulnerability {
                name
              }
              ... on Incident {
                name
                first_seen
                last_seen
              }
              ... on StixCyberObservable {
                observable_value
              }
              ... on StixFile {
                observableName: name
              }
            }
          }
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceStixCoreObjects);
