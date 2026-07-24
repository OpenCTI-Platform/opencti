import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import { useTheme } from '@mui/styles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import { Box, ListItemButton, Tooltip } from '@mui/material';
import { InformationOutline } from 'mdi-material-ui';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { SecurityCoverageVulnerabilities_securityCoverage$data } from './__generated__/SecurityCoverageVulnerabilities_securityCoverage.graphql';
import SecurityCoverageScores from './SecurityCoverageScores';
import ItemIcon from '../../../../components/ItemIcon';
import StixCoreRelationshipPopover from '../../common/stix_core_relationships/StixCoreRelationshipPopover';
import Label from '../../../../components/common/label/Label';
import Alert from '../../../../components/Alert';

const MAX_VULNERABILITIES = 500;

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
  const globalCount = securityCoverage.vulnerabilities?.pageInfo?.globalCount ?? 0;
  return (
    <div>
      <Label
        action={(
          <Tooltip title={t_i18n('Average coverage score from Security Coverage Result(s)')}>
            <InformationOutline fontSize="small" color="primary" />
          </Tooltip>
        )}
      >
        {t_i18n('Vulnerabilities')}
      </Label>
      {globalCount > MAX_VULNERABILITIES && (
        <Alert
          severity="warning"
          style={{ marginBottom: 10 }}
          content={t_i18n(
            'Showing {max} of {count} vulnerabilities. Some results are not displayed.',
            { values: { max: MAX_VULNERABILITIES, count: globalCount } },
          )}
        />
      )}
      <List sx={{ maxHeight: 10 * 44, overflowY: 'auto' }}>
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
                secondaryAction={(
                  <StixCoreRelationshipPopover
                    objectId={securityCoverage.id}
                    connectionKey="Pagination_vulnerabilities"
                    stixCoreRelationshipId={vulnerabilityEdge.node.id}
                    paginationOptions={paginationOptions}
                    isCoverage={true}
                  />
                )}
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
                    primary={(
                      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        <Typography variant="body2" component="span" sx={{ flex: '1 1 10%' }}>{vulnerability?.name}</Typography>
                        <Box sx={{ flex: '1 1 auto', display: 'flex', justifyContent: 'center' }}>
                          <SecurityCoverageScores
                            coverage_information={coverage}
                            variant="header"
                          />
                        </Box>
                      </Box>
                    )}
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
        vulnerabilities: stixCoreRelationshipsFromResults(
          relationship_type: "has-covered"
          orderBy: created_at
          orderMode: asc
          toTypes: ["Vulnerability"]
          first: 500
        ) @connection(key: "Pagination_vulnerabilities") {
          pageInfo {
            globalCount
          }
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
