import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import { Stack, Typography } from '@mui/material';
import Divider from '@mui/material/Divider';
import { EMPTY_VALUE } from '../../../../utils/String';
import SecurityCoverageInformation from '@components/analyses/security_coverages/SecurityCoverageInformation';
import { graphql, useFragment } from 'react-relay';
import { SecurityCoverageMainInfo_securityCoverage$key } from './__generated__/SecurityCoverageMainInfo_securityCoverage.graphql';

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
    }
`;

interface Props {
  securityCoverage: SecurityCoverageMainInfo_securityCoverage$key;
}

const SecurityCoverageMainInfo: FunctionComponent<Props> = ({
  securityCoverage,
}) => {
  const { t_i18n, fndt } = useFormatter();
  const data = useFragment(securityCoverageEntitiesMainInfoFragment, securityCoverage);
  return (
    <Card title={t_i18n('Coverage information')} sx={{ alignContent: 'center' }}>
      <Stack
        direction="row"
        divider={<Divider orientation="vertical" flexItem />}
        spacing={2}
        alignItems="center"
      >
        <Stack sx={{ flexGrow: 1 }} spacing={2}>
          <Stack direction="row" spacing={1}>
            <Label>{t_i18n('Last result')}</Label>
            <Typography>{data.coverage_last_result ? fndt(data.coverage_last_result) : EMPTY_VALUE} </Typography>
          </Stack>
          <Stack direction="row" spacing={1}>
            <Label>{t_i18n('Valid from')}</Label>
            <Typography>{data.coverage_valid_from ? fndt(data.coverage_valid_from) : EMPTY_VALUE}</Typography>
          </Stack>
          <Stack direction="row" spacing={1}>
            <Label>{t_i18n('Valid until')}</Label>
            <Typography><Typography>{data.coverage_valid_to ? fndt(data.coverage_valid_to) : EMPTY_VALUE}</Typography></Typography>
          </Stack>
        </Stack>

        <Stack id="testname" sx={{ flexGrow: 1, alignItems: 'center' }}>
          <SecurityCoverageInformation coverage_information={data.coverage_information ?? []} variant="details" />
        </Stack>
      </Stack>
    </Card>
  );
};

export default SecurityCoverageMainInfo;
