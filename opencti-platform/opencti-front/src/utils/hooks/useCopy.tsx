import { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import { fetchQuery, MESSAGING$ } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import { maxNumberOfObservablesToCopy } from '../../private/components/data/ToolBar';
import { FilterGroup } from '../filters/filtersUtils';

interface UseCopyProps<T> {
  filters?: FilterGroup;
  searchTerm: string;
  deselectedIds: string[];
  selectedValues: string[];
  query: GraphQLTaggedNode;
  elementId?: string;
  getValuesForCopy: (el: T) => { id: string; value: string }[];
}

const useCopy = <T extends OperationType['response']>(
  {
    filters,
    searchTerm,
    deselectedIds,
    selectedValues,
    query,
    elementId,
    getValuesForCopy,
  }: UseCopyProps<T>,
  selectAll = false,
) => {
  const { t } = useFormatter();
  return () => {
    let computedSelectedValues = selectedValues;
    if (selectAll) {
      (elementId
        ? fetchQuery(query, {
          id: elementId,
          search: searchTerm,
          filters,
          count: maxNumberOfObservablesToCopy,
        })
        : fetchQuery(query, {
          search: searchTerm,
          filters,
          count: maxNumberOfObservablesToCopy,
        })
      )
        .toPromise()
        .then((data) => {
          const observables = getValuesForCopy(data as T);
          computedSelectedValues = observables
            .filter(({ id }) => !deselectedIds.includes(id))
            .map(({ value }) => value);
          const toBeCopied = computedSelectedValues.join('\n');
          navigator.clipboard.writeText(toBeCopied);
          MESSAGING$.notifySuccess(t('Elements successfully copied'));
        });
    } else {
      const toBeCopied = computedSelectedValues.join('\n');
      navigator.clipboard.writeText(toBeCopied);
      MESSAGING$.notifySuccess(t('Elements successfully copied'));
    }
  };
};

export default useCopy;
