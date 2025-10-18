import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { LockPattern } from 'mdi-material-ui';
import { createFragmentContainer, graphql } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { RecordSourceSelectorProxy, RecordProxy } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import AddSecurityPlatforms from './AddSecurityPlatforms';
import { SecurityCoverageSecurityPlatforms_securityCoverage$data } from './__generated__/SecurityCoverageSecurityPlatforms_securityCoverage.graphql';

const removeMutation = graphql`
  mutation SecurityCoverageSecurityPlatformsRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

interface SecurityCoverageSecurityPlatformsProps {
  securityCoverage: SecurityCoverageSecurityPlatforms_securityCoverage$data;
}

const SecurityCoverageSecurityPlatformsComponent: FunctionComponent<SecurityCoverageSecurityPlatformsProps> = ({
  securityCoverage,
}) => {
  const { t_i18n } = useFormatter();

  const removeSecurityPlatform = (securityPlatformEdge: {
    node: {
      id: string;
      to: {
        id?: string;
      } | null | undefined;
    };
  }) => {
    if (!securityPlatformEdge.node.to?.id) return;
    commitMutation({
      mutation: removeMutation,
      variables: {
        fromId: securityCoverage.id,
        toId: securityPlatformEdge.node.to.id,
        relationship_type: 'has-covered',
      },
      updater: (store: RecordSourceSelectorProxy) => {
        const node = store.get(securityCoverage.id);
        if (node) {
          const securityPlatforms = node.getLinkedRecord('securityPlatforms');
          if (securityPlatforms) {
            const edges = securityPlatforms.getLinkedRecords('edges');
            const newEdges = (edges || []).filter(
              (n) => n?.getLinkedRecord('node')?.getValue('id')
                !== securityPlatformEdge.node.id
            ) as RecordProxy[];
            securityPlatforms.setLinkedRecords(newEdges, 'edges');
          }
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Security Platforms')}
        </Typography>
        <AddSecurityPlatforms
          securityCoverage={securityCoverage}
          securityCoverageSecurityPlatforms={securityCoverage.securityPlatforms?.edges || []}
        />
      </div>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <FieldOrEmpty source={securityCoverage.securityPlatforms?.edges || []}>
          {(securityCoverage.securityPlatforms?.edges || []).map((securityPlatformEdge) => {
            const securityPlatform = securityPlatformEdge.node.to;
            return (
              <ListItem
                key={securityPlatformEdge.node.id}
                dense={true}
                divider={true}
                disablePadding={true}
                secondaryAction={
                  <IconButton
                    aria-label="Remove"
                    onClick={() => removeSecurityPlatform(securityPlatformEdge)}
                    size="large"
                  >
                    <LinkOff/>
                  </IconButton>
                }
              >
                <ListItemButton
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform?.id}`}
                >
                  <ListItemIcon>
                    <LockPattern color="primary"/>
                  </ListItemIcon>
                  <ListItemText primary={securityPlatform?.name}/>
                </ListItemButton>
              </ListItem>
            );
          })}
        </FieldOrEmpty>
      </List>
    </div>
  );
};

const SecurityCoverageSecurityPlatforms = createFragmentContainer(
  SecurityCoverageSecurityPlatformsComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageSecurityPlatforms_securityCoverage on SecurityCoverage {
        id
        name
        parent_types
        entity_type
        securityPlatforms: stixCoreRelationships(
          relationship_type: "has-covered"
          toTypes: ["SecurityPlatform"]
        ) {
          edges {
            node {
              id
              to {
                ... on SecurityPlatform {
                  id
                  parent_types
                  name
                  description
                }
              }
            }
          }
        }
      }
    `,
  },
);

export default SecurityCoverageSecurityPlatforms;
