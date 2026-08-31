import React, { FunctionComponent, useMemo } from 'react';
import Typography from '@mui/material/Typography';
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
import SecurityCoverageCoveredList from './SecurityCoverageCoveredList';
import ItemIcon from '../../../../components/ItemIcon';
import Label from '../../../../components/common/label/Label';
import Alert from '../../../../components/Alert';
import { dedupeCoveredEntities } from './securityCoverageAggregation';

const MAX_VULNERABILITIES = 5000;

interface SecurityCoverageVulnerabilitiesProps {
  securityCoverage: SecurityCoverageVulnerabilities_securityCoverage$data;
}

const SecurityCoverageVulnerabilitiesComponent: FunctionComponent<SecurityCoverageVulnerabilitiesProps> = ({
  securityCoverage,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const globalCount = securityCoverage.vulnerabilities?.count ?? 0;
  const vulnerabilityEntities = useMemo(
    () => dedupeCoveredEntities(securityCoverage.vulnerabilities?.entities ?? []),
    [securityCoverage.vulnerabilities?.entities],
  );
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
      <FieldOrEmpty source={vulnerabilityEntities}>
        <SecurityCoverageCoveredList
          entities={vulnerabilityEntities}
          rowRenderer={(vulnerabilityEntity) => {
            const vulnerability = vulnerabilityEntity.to;
            const coverage = vulnerabilityEntity.coverage_information || [];
            return (
              <ListItem
                key={vulnerabilityEntity.relationship_id}
                dense={true}
                divider={true}
                disablePadding={true}
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
                        <Typography variant="body2" component="span" noWrap sx={{ flex: '1 1 10%' }}>{vulnerability?.name}</Typography>
                        <Box sx={{ flex: '1 1 auto', display: 'flex', justifyContent: 'end' }}>
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
          }}
        />
      </FieldOrEmpty>
    </div>
  );
};

const SecurityCoverageVulnerabilities = createFragmentContainer(
  SecurityCoverageVulnerabilitiesComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageVulnerabilities_securityCoverage on SecurityCoverage {
        vulnerabilities: coveredVulnerabilities(
          orderBy: created_at
          orderMode: asc
          first: 5000
        ) {
          count
          entities {
            relationship_id
            coverage_information {
              coverage_name
              coverage_score
            }
            to {
              id
              parent_types
              name
              description
            }
          }
        }
      }
    `,
  },
);

export default SecurityCoverageVulnerabilities;
