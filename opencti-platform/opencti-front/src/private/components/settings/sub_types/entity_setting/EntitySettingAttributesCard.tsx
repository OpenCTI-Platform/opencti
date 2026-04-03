import Card from '@common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import SearchInput from '../../../../../components/SearchInput';
import EntitySettingAttributes from './EntitySettingAttributes';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { useOutletContext } from 'react-router-dom';
import { SubTypeQuery, SubTypeQuery$variables } from '../__generated__/SubTypeQuery.graphql';
import ErrorNotFound from '../../../../../components/ErrorNotFound';

const EntitySettingAttributesCard = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useOutletContext<{ subType: SubTypeQuery['response']['subType'] }>();

  if (!subType) return <ErrorNotFound />;
  if (!subType.settings) return <ErrorNotFound />;

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
