import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import List from '@mui/material/List';
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
    const { t, fd, classes, externalReference } = this.props;
    const stixCoreObjects = R.map(
      (n) => n.node,
      externalReference.references.edges,
    );
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Linked objects')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
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
                  }${
                    stixCoreObject.name
                    || stixCoreObject.observable_value
                    || stixCoreObject.attribute_abstract
                    || stixCoreObject.content
                    || stixCoreObject.opinion
                    || `${fd(stixCoreObject.first_observed)} - ${fd(
                      stixCoreObject.last_observed,
                    )}`
                  }`}
                  secondary={
                    <Markdown
                      remarkPlugins={[remarkGfm, remarkParse]}
                      parserOptions={{ commonmark: true }}
                      className="markdown"
                    >
                      {truncate(
                        stixCoreObject.description
                          || stixCoreObject.x_opencti_description
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
        references(types: ["Stix-Core-Object"]) {
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
                description
                x_mitre_id
              }
              ... on Campaign {
                name
                description
              }
              ... on Report {
                name
                description
              }
              ... on ObservedData {
                name
              }
              ... on CourseOfAction {
                name
                description
              }
              ... on Individual {
                name
                description
              }
              ... on Organization {
                name
                description
              }
              ... on Sector {
                name
                description
              }
              ... on System {
                name
                description
              }
              ... on Indicator {
                name
                description
              }
              ... on Infrastructure {
                name
                description
              }
              ... on IntrusionSet {
                name
                description
              }
              ... on Position {
                name
                description
              }
              ... on City {
                name
                description
              }
              ... on Country {
                name
                description
              }
              ... on Region {
                name
                description
              }
              ... on Malware {
                name
                description
              }
              ... on ThreatActor {
                name
                description
              }
              ... on Tool {
                name
                description
              }
              ... on Vulnerability {
                name
                description
              }
              ... on Incident {
                name
                description
              }
              ... on StixCyberObservable {
                observable_value
                x_opencti_description
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
