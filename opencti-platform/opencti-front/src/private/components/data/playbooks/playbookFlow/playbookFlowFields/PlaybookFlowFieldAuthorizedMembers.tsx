import { useFormatter } from '../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import ObjectMembersField from '../../../../common/form/ObjectMembersField';

const PlaybookFlowFieldAuthorizedMembers = () => {
  const { t_i18n } = useFormatter();

  return (
    <ObjectMembersField
      multiple
      name="authorized_members"
      label={t_i18n('Targets')}
      style={fieldSpacingContainerStyle}
    />
  );
};

export default PlaybookFlowFieldAuthorizedMembers;
