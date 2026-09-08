import Label from '@common/label/Label';
import SecurityCoverageScores from './security_coverage_scores/SecurityCoverageScores';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { CoverageInformation } from './SecurityCoverage-types';

interface SecurityCoverageInformationProps {
  coverage_information: ReadonlyArray<CoverageInformation> | null | undefined;
}

const SecurityCoverageInformation = ({ coverage_information }: SecurityCoverageInformationProps) => {
  const { t_i18n } = useFormatter();
  const hasCoverageInformation = (coverage_information ?? []).length > 0;

  return (
    <div>
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
    </div>
  );
};

export default SecurityCoverageInformation;
