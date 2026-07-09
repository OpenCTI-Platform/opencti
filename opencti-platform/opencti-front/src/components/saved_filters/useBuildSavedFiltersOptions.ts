import { SavedFiltersAutocompleteOptionType } from 'src/components/saved_filters/SavedFilterSelection';
import useAuth from 'src/utils/hooks/useAuth';

const useBuildSavedFiltersOptions = (data): SavedFiltersAutocompleteOptionType[] => {
  const { me } = useAuth();
  const options = data.map((item) => {
    const isOwner = item.creator_id === me.id;
    const ownerMember = item.authorizedMembers?.find((m) => m.member_id === item.creator_id);
    const ownerName = ownerMember?.name ?? '';

    return {
      label: item.name,
      value: item,
      isOwner,
      ownerName: isOwner ? undefined : ownerName,
      canManage: item.currentUserAccessRight === 'admin',
    };
  });

  // Sort options: "My filters" first, then "Shared with me"; alphabetically within each group
  return [...options].sort((a, b) => {
    if (a.isOwner && !b.isOwner) return -1;
    if (!a.isOwner && b.isOwner) return 1;
    return a.label.localeCompare(b.label);
  });
};

export default useBuildSavedFiltersOptions;
