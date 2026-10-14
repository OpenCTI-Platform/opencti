import { Stack, Typography } from '@mui/material';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from '../../../../../components/common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import SecurityCoverageScores from '../security_coverage_scores/SecurityCoverageScores';
import StixCoreObjectLabels from '../../../common/stix_core_objects/StixCoreObjectLabels';
import { EditableSecurityCoverageResult } from './SecurityCoverageResultForm-utils';

interface SecurityCoverageResultSelectStepProps<T extends EditableSecurityCoverageResult> {
  results: readonly T[];
  onSelect: (result: T) => void;
  onCancel: () => void;
}

const SecurityCoverageResultSelectStep = <T extends EditableSecurityCoverageResult>({
  results,
  onSelect,
  onCancel,
}: SecurityCoverageResultSelectStepProps<T>) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Stack gap={1}>
        {results.map((result) => (
          <Stack
            key={result.id}
            direction="row"
            alignItems="center"
            gap={2}
          >
            <Typography sx={{ flex: 2 }} noWrap>{result.name}</Typography>
            <div style={{ flex: 1 }}>
              <SecurityCoverageScores
                coverage_information={result.coverage_information}
                variant="header"
              />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <StixCoreObjectLabels labels={result.objectLabel} />
            </div>
            <Button onClick={() => onSelect(result)}>
              {t_i18n('Update')}
            </Button>
          </Stack>
        ))}
      </Stack>
      <FormButtonContainer>
        <Button variant="tertiary" onClick={onCancel}>
          {t_i18n('Cancel')}
        </Button>
      </FormButtonContainer>
    </>
  );
};

export default SecurityCoverageResultSelectStep;
