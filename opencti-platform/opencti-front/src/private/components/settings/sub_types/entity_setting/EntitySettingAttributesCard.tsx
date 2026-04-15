import Card from '@common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import SearchInput from '../../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { SubTypeQuery$variables } from '../__generated__/SubTypeQuery.graphql';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import EntitySettingAttributes from './EntitySettingAttributes';

const EntitySettingAttributesCard = () => {
  const { t_i18n } = useFormatter();

  const { subType } = useSubTypeOutletContext();

  const LOCAL_STORAGE_KEY = `${subType.id}-attributes`;
  const { viewStorage, helpers } = usePaginationLocalStorage<SubTypeQuery$variables>(
    LOCAL_STORAGE_KEY,
    { searchTerm: '' },
  );
  const { searchTerm } = viewStorage;

  return (
    <Card
      title={t_i18n('Attributes')}
      titleSx={{ alignItems: 'end' }}
      sx={{ paddingTop: 0, paddingBottom: 0 }}
      action={(
        <SearchInput
          variant="thin"
          onSubmit={helpers.handleSearch}
          keyword={searchTerm}
        />
      )}
    >
      <EntitySettingAttributes
        entitySettingsData={subType.settings}
        searchTerm={searchTerm}
      />
    </Card>
  );
};

export default EntitySettingAttributesCard;
