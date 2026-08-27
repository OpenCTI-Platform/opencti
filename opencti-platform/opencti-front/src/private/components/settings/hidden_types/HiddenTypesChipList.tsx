import { Chip } from '@filigran/design-system';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const HiddenTypesChipList = ({
  hiddenTypes = [],
}: {
  hiddenTypes: readonly string[];
}) => {
  const { t_i18n } = useFormatter();

  const hiddenTypesGlobal = useEntitySettings()
    .filter((entitySetting) => entitySetting.platform_hidden_type === true)
    .map((hiddenType) => hiddenType.target_type);
  const diff = hiddenTypesGlobal.filter((hiddenTypeGlobal) => !hiddenTypes?.includes(hiddenTypeGlobal));

  return (
    <>
      <Label>
        {t_i18n('Hidden entity types')}
      </Label>
      <FieldOrEmpty source={hiddenTypesGlobal.concat(hiddenTypes)}>
        {diff.map((hiddenTypeGlobal) => (
          <Chip
            key={hiddenTypeGlobal}
            severity="neutral"
            label={t_i18n(`entity_${hiddenTypeGlobal}`)}
            style={{ margin: '0 5px 5px 0' }}
          />
        ))}
        {hiddenTypes.map((hiddenType) => (
          <Chip
            key={hiddenType}
            severity="neutral"
            label={t_i18n(`entity_${hiddenType}`)}
            style={{ margin: '0 5px 5px 0' }}
          />
        ))}
      </FieldOrEmpty>
    </>
  );
};

export default HiddenTypesChipList;
