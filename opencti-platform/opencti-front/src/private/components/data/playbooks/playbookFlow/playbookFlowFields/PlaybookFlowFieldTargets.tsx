import { useFormatter } from '../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import ObjectMembersField from '../../../../common/form/ObjectMembersField';

const PlaybookFlowFieldTargets = () => {
  const { t_i18n } = useFormatter();

  return (
    <ObjectMembersField
      multiple
      name="targets"
      label={t_i18n('Targets')}
      style={fieldSpacingContainerStyle}
      dynamicKeysForPlaybooks
    />
  );
};

export default PlaybookFlowFieldTargets;
