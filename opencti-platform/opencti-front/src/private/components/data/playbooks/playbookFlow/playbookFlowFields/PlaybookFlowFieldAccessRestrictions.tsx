import { Field } from 'formik';
import { useFormatter } from '../../../../../../components/i18n';
import AuthorizedMembersField from '../../../../common/form/AuthorizedMembersField';

const PlaybookFlowFieldAccessRestrictions = () => {
  const { t_i18n } = useFormatter();

  return (
    <Field
      hideInfo
      adminDefault
      enableAccesses
      showAllMembersLine
      dynamicKeysForPlaybooks
      name="access_restrictions"
      label={t_i18n('Access restrictions')}
      component={AuthorizedMembersField}
    />
  );
};

export default PlaybookFlowFieldAccessRestrictions;
