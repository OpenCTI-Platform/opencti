import React from 'react';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { computeLink } from '../../../../utils/Entity';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 4,
  },
}));

const ExternalReferenceStixCoreObjectsComponent = ({ externalReference }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const stixCoreObjects = R.map(
    (n) => n?.node,
    externalReference.references?.edges ?? [],
  );
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Linked objects')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <List classes={{ root: classes.list }}>
          {stixCoreObjects.map((stixCoreObjectOrRelationship) => (
            <ListItem
              key={stixCoreObjectOrRelationship.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              component={Link}
              to={`${computeLink(stixCoreObjectOrRelationship)}`}
            >
              <ListItemIcon>
                <ItemIcon type={stixCoreObjectOrRelationship.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={stixCoreObjectOrRelationship.representative?.main}
                primaryTypographyProps={{ style: { wordWrap: 'break-word' } }}
                secondary={truncate(stixCoreObjectOrRelationship.representative?.secondary, 150)}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </div>
  );
};

const ExternalReferenceStixCoreObjects = createFragmentContainer(
  ExternalReferenceStixCoreObjectsComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceStixCoreObjects_externalReference on ExternalReference {
        id
        references(types: ["Stix-Core-Object", "Stix-Core-Relationship", "Stix-Sighting-Relationship"]) {
          edges {
            node {
              ... on StixObject {
                id
                entity_type
                representative {
                  main
                  secondary
                }
              }
              ... on StixRelationship {
                id
                entity_type
                relationship_type
                representative {
                  main
                  secondary
                }
                from {
                  ... on StixObject {
                    id
                    entity_type
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
);

export default ExternalReferenceStixCoreObjects;
