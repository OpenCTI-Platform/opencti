import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import { useTheme } from '@mui/styles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import { Box, ListItemButton } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import AddVulnerabilities from './AddVulnerabilities';
import { SecurityCoverageVulnerabilities_securityCoverage$data } from './__generated__/SecurityCoverageVulnerabilities_securityCoverage.graphql';
import SecurityCoverageInformation from './SecurityCoverageInformation';
import ItemIcon from '../../../../components/ItemIcon';
import StixCoreRelationshipPopover from '../../common/stix_core_relationships/StixCoreRelationshipPopover';

interface SecurityCoverageVulnerabilitiesProps {
  securityCoverage: SecurityCoverageVulnerabilities_securityCoverage$data;
}

const SecurityCoverageVulnerabilitiesComponent: FunctionComponent<SecurityCoverageVulnerabilitiesProps> = ({
  securityCoverage,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const paginationOptions = {
    orderBy: 'created_at',
    orderMode: 'asc',
    relationship_type: 'has-covered',
    toTypes: ['Vulnerability'],
  };
  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Vulnerabilities')}
        </Typography>
        <AddVulnerabilities securityCoverage={securityCoverage} paginationOptions={paginationOptions} />
      </div>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <FieldOrEmpty source={securityCoverage.vulnerabilities?.edges}>
          {securityCoverage.vulnerabilities?.edges?.map((vulnerabilityEdge) => {
            const vulnerability = vulnerabilityEdge.node.to;
            const coverage = vulnerabilityEdge.node.coverage_information || [];
            return (
              <ListItem
                key={vulnerabilityEdge.node.id}
                dense={true}
                divider={true}
                disablePadding={true}
                secondaryAction={
                  <StixCoreRelationshipPopover
                    objectId={securityCoverage.id}
                    connectionKey={'Pagination_vulnerabilities'}
                    stixCoreRelationshipId={vulnerabilityEdge.node.id}
                    paginationOptions={paginationOptions}
                    isCoverage={true}
                  />
                }
              >
                <ListItemButton
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability?.id}`}
                  style={{ width: '100%' }}
                >
                  <ListItemIcon>
                    <ItemIcon color={theme.palette.primary.main} type="vulnerability" />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        <Typography variant="body2" component="span" sx={{ flex: '1 1 10%' }}>{vulnerability?.name}</Typography>
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

const SecurityCoverageVulnerabilities = createFragmentContainer(
  SecurityCoverageVulnerabilitiesComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageVulnerabilities_securityCoverage on SecurityCoverage {
        id
        name
        parent_types
        entity_type
        vulnerabilities: stixCoreRelationships(
          relationship_type: "has-covered"
          orderBy: created_at
          orderMode: asc
          toTypes: ["Vulnerability"]
          first: 25
        ) @connection(key: "Pagination_vulnerabilities") {
          edges {
            node {
              id
              coverage_information {
                coverage_name
                coverage_score
              }
              to {
                ... on Vulnerability {
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

export default SecurityCoverageVulnerabilities;
