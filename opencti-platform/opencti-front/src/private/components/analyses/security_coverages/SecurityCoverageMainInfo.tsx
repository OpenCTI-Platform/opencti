import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import { Stack, Typography } from '@mui/material';
// fds:keep-mui the library Tooltip is a compound API; this call site converts with the wider Tooltip wave
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Divider from '@mui/material/Divider';
import { EMPTY_VALUE } from '../../../../utils/String';
import SecurityCoverageScores from '@components/analyses/security_coverages/security_coverage_scores/SecurityCoverageScores';
import { graphql, useFragment } from 'react-relay';
import { SecurityCoverageMainInfo_securityCoverage$key } from './__generated__/SecurityCoverageMainInfo_securityCoverage.graphql';
import { resolveSelectedResult } from './securityCoverageResultScope';

const securityCoverageEntitiesMainInfoFragment = graphql`
    fragment SecurityCoverageMainInfo_securityCoverage on SecurityCoverage {
        id
        coverage_last_result
        coverage_valid_from
        coverage_valid_to
        coverage_information {
            coverage_name
            coverage_score
        }
        results {
            id
            coverage_last_result
            coverage_valid_from
            coverage_valid_to
            coverage_information {
                coverage_name
                coverage_score
            }
        }
    }
`;

interface Props {
  securityCoverage: SecurityCoverageMainInfo_securityCoverage$key;
  selectedResultId: string | null;
}

const SecurityCoverageMainInfo: FunctionComponent<Props> = ({
  securityCoverage,
  selectedResultId,
}) => {
  const { t_i18n, fndt } = useFormatter();
  const data = useFragment(securityCoverageEntitiesMainInfoFragment, securityCoverage);
  // The selected result replaces the coverage averages; an unknown result falls back to them.
  const selectedResult = resolveSelectedResult(data.results ?? [], selectedResultId);
  const scope = selectedResult ?? data;
  return (
    <Card
      title={(
        <Stack
          direction="row"
          spacing={1}
          sx={{
            alignItems: 'center',
          }}
        >
          <span>{t_i18n('Coverage information')}</span>
          <Tooltip title={selectedResult ? t_i18n('Coverage score from the selected Security Coverage Result') : t_i18n('Average coverage score from Security Coverage Result(s)')}>
            <InformationOutline fontSize="small" color="primary" />
          </Tooltip>
        </Stack>
      )}
      sx={{ alignContent: 'center' }}
    >
      <Stack
        direction="row"
        divider={<Divider orientation="vertical" flexItem />}
        spacing={2}
        sx={{
          alignItems: 'center',
        }}
      >
        <Stack sx={{ flexGrow: 1 }} spacing={2}>
          <Stack direction="row" spacing={1}>
            <Label>{t_i18n('Last result')}</Label>
            <Typography>{scope.coverage_last_result ? fndt(scope.coverage_last_result) : EMPTY_VALUE} </Typography>
          </Stack>
          <Stack direction="row" spacing={1}>
            <Label>{t_i18n('Valid from')}</Label>
            <Typography>{scope.coverage_valid_from ? fndt(scope.coverage_valid_from) : EMPTY_VALUE}</Typography>
          </Stack>
          <Stack direction="row" spacing={1}>
            <Label>{t_i18n('Valid until')}</Label>
            <Typography><Typography>{scope.coverage_valid_to ? fndt(scope.coverage_valid_to) : EMPTY_VALUE}</Typography></Typography>
          </Stack>
        </Stack>

        <Stack id="testname" sx={{ flexGrow: 1, alignItems: 'center' }}>
          <SecurityCoverageScores
            coverage_information={scope.coverage_information ?? []}
            variant="details"
          />
        </Stack>
      </Stack>
    </Card>
  );
};

export default SecurityCoverageMainInfo;
