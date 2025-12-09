import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import { ListItemButton } from '@mui/material';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { useComputeLink } from '../../../../utils/hooks/useAppData';
import Card from '@common/card/Card';

const ExternalReferenceStixCoreObjectsComponent = ({ externalReference }) => {
  const { t_i18n } = useFormatter();
  const computeLink = useComputeLink();

  const stixCoreObjects = (externalReference.references?.edges ?? [])
    .map((n) => n?.node);

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Linked objects')}>
        <List>
          {stixCoreObjects.map((stixCoreObjectOrRelationship) => (
            <ListItemButton
              key={stixCoreObjectOrRelationship.id}
              divider={true}
              component={Link}
              to={`${computeLink(stixCoreObjectOrRelationship)}`}
            >
              <ListItemIcon>
                <ItemIcon type={stixCoreObjectOrRelationship.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={stixCoreObjectOrRelationship.representative?.main}
                secondary={truncate(stixCoreObjectOrRelationship.representative?.secondary, 150)}
                slotProps={{
                  primary: { style: { wordWrap: 'break-word' } },
                }}
              />
            </ListItemButton>
          ))}
        </List>
      </Card>
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
