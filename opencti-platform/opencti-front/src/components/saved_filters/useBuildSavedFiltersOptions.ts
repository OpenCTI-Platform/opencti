import { SavedFiltersAutocompleteOptionType, SavedFiltersSelectionData, WidgetSavedFilterScope } from 'src/components/saved_filters/SavedFilterSelection';
import useAuth from 'src/utils/hooks/useAuth';

/**
 * Builds the list of options consumed by `SavedFiltersAutocomplete` from the raw
 * saved-filters data returned by the API.
 *
 * The returned options are sorted with the user's own filters ("My filters")
 * first, then those "Shared with me", each group ordered alphabetically by label.
 *
 * @param data  Raw saved-filter nodes from the `savedFilters` query.
 * @param scope Optional widget perspective used to disable non-matching filters in widgets.
 * @returns Sorted, display-ready autocomplete saved filters options.
 */
const useBuildSavedFiltersOptions = (
  data: SavedFiltersSelectionData[],
  scope?: WidgetSavedFilterScope,
): SavedFiltersAutocompleteOptionType[] => {
  const { me } = useAuth();
  const options = data.map((item) => {
    const isOwner = item.creator_id === me.id;
    const ownerMember = item.authorizedMembers?.find((m) => m.member_id === item.creator_id);
    const ownerName = ownerMember?.name ?? '';

    // in widgets, saved filters not corresponding to the widget perspective are disabled
    let disabled = false;
    if (scope) {
      if (scope === 'stix-core-relationship' && item.scope !== 'relationships') {
        disabled = true;
      } else if (scope === 'History' && !item.scope.includes('audit')) {
        disabled = true;
      } else if (scope === 'Stix-Core-Object'
        && (item.scope.includes('audit') || item.scope === 'relationships')) {
        disabled = true;
      }
    }

    return {
      label: item.name,
      value: item,
      isOwner,
      ownerName: isOwner ? undefined : ownerName,
      canManage: item.currentUserAccessRight === 'admin',
      scope: item.scope,
      disabled,
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
