import { useFormatter } from '../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import PirField from '../../../../common/form/PirField';

const PlaybookFlowFieldInPirFilters = () => {
  const { t_i18n } = useFormatter();

  return (
    <PirField
      multiple
      name="inPirFilters"
      style={fieldSpacingContainerStyle}
      helpertext={t_i18n('If no PIR is selected, the playbook will look for any PIR')}
    />
  );
};

export default PlaybookFlowFieldInPirFilters;
