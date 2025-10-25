import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import { Box, ListItemButton } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import AddSecurityPlatforms from './AddSecurityPlatforms';
import { SecurityCoverageSecurityPlatforms_securityCoverage$data } from './__generated__/SecurityCoverageSecurityPlatforms_securityCoverage.graphql';
import SecurityCoverageInformation from './SecurityCoverageInformation';
import ItemIcon from '../../../../components/ItemIcon';
import StixCoreRelationshipPopover from '../../common/stix_core_relationships/StixCoreRelationshipPopover';

interface SecurityCoverageSecurityPlatformsProps {
  securityCoverage: SecurityCoverageSecurityPlatforms_securityCoverage$data;
}

const SecurityCoverageSecurityPlatformsComponent: FunctionComponent<SecurityCoverageSecurityPlatformsProps> = ({
  securityCoverage,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const paginationOptions = {
    orderBy: 'created_at',
    orderMode: 'asc',
    relationship_type: 'has-covered',
    toTypes: ['SecurityPlatform'],
  };
  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Security Platforms')}
        </Typography>
        <AddSecurityPlatforms securityCoverage={securityCoverage} paginationOptions={paginationOptions} />
      </div>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <FieldOrEmpty source={securityCoverage.securityPlatforms?.edges || []}>
          {(securityCoverage.securityPlatforms?.edges || []).map((securityPlatformEdge) => {
            const securityPlatform = securityPlatformEdge.node.to;
            const coverage = securityPlatformEdge.node.coverage_information || [];
            return (
              <ListItem
                key={securityPlatformEdge.node.id}
                dense={true}
                divider={true}
                disablePadding={true}
                secondaryAction={
                  <StixCoreRelationshipPopover
                    objectId={securityCoverage.id}
                    connectionKey={'Pagination_securityPlatforms'}
                    stixCoreRelationshipId={securityPlatformEdge.node.id}
                    paginationOptions={paginationOptions}
                    isCoverage={true}
                  />
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
                      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        <Typography variant="body2" component="span" sx={{ flex: '1 1 10%' }}>{securityPlatform?.name}</Typography>
                        <Box sx={{ flex: '1 1 auto', display: 'flex', justifyContent: 'center' }}>
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
          orderBy: created_at
          orderMode: asc
          relationship_type: "has-covered"
          toTypes: ["SecurityPlatform"]
          first: 25
        ) @connection(key: "Pagination_securityPlatforms") {
          edges {
            node {
              id
              coverage_information {
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
