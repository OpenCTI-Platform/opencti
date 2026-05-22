import Label from '@common/label/Label';
import { Box } from '@mui/material';
import SecurityCoverageScores from './SecurityCoverageScores';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';

interface SecurityCoverageInformationProps {
  coverage_information: ReadonlyArray<{
    readonly coverage_name: string;
    readonly coverage_score: number;
  }> | null | undefined;
}

const SecurityCoverageInformation = ({ coverage_information }: SecurityCoverageInformationProps) => {
  const { t_i18n } = useFormatter();
  const hasCoverageInformation = (coverage_information ?? []).length > 0;

  return (
    <Box sx={{ marginBottom: 2 }}>
      <Label>
        {t_i18n('Is covered')}
      </Label>
      <ItemBoolean
        status={hasCoverageInformation}
        label={hasCoverageInformation ? t_i18n('True') : t_i18n('False')}
      />
      {hasCoverageInformation && (
        <>
          <Label sx={{ marginTop: 2 }}>
            {t_i18n('Coverage scores')}
          </Label>
          <SecurityCoverageScores
            coverage_information={coverage_information}
            variant="details"
          />
        </>
      )}
    </Box>
  );
};

export default SecurityCoverageInformation;
