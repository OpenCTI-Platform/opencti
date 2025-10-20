import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { createFragmentContainer, graphql } from 'react-relay';
import { Box, ListItemButton } from '@mui/material';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { type Theme } from '../../../../components/Theme.d';
import { commitMutation } from '../../../../relay/environment';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import AddSecurityPlatforms from './AddSecurityPlatforms';
import { SecurityCoverageSecurityPlatforms_securityCoverage$data } from './__generated__/SecurityCoverageSecurityPlatforms_securityCoverage.graphql';
import SecurityCoverageInformation from './SecurityCoverageInformation';
import ItemIcon from '../../../../components/ItemIcon';

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
  const theme = useTheme<Theme>();

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
        deleteNodeFromEdge(
          store,
          'securityPlatforms',
          securityCoverage.id,
          securityPlatformEdge.node.id,
          {
            relationship_type: 'has-covered',
            toTypes: ['SecurityPlatform'],
          },
        );
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
            const coverage = securityPlatformEdge.node.coverage || [];
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
                  style={{ width: '100%' }}
                >
                  <ListItemIcon>
                    <ItemIcon color={theme.palette.primary.main} type="security-platform" />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                        <Typography variant="body2" component="span" sx={{ flexGrow: 1 }}>{securityPlatform?.name}</Typography>
                        <Box sx={{ ml: 'auto', mr: 2 }}>
                          <SecurityCoverageInformation
                            coverage_information={coverage}
                            variant="header"
                          />
                        </Box>
                      </Box>
                    }
                  />
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
          first: 200
        ) @connection(key: "Pagination_securityPlatforms") {
          edges {
            node {
              id
              coverage {
                coverage_name
                coverage_score
              }
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
