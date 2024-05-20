import { fetchQuery } from 'src/relay/environment';
import searchStixCoreObjectsByRepresentativeQuery from '../dialog/BulkRelationDialogSearchQuery';

export type StixCoreResultsType = {
  searchTerm: string;
  stixCoreObjects: EdgeStuffType;
};
export type EdgeStuffType = {
  edges: NodeStuffType[];
};
export type NodeStuffType = {
  node: StixCoreEntityType;
};
export type StixCoreEntityType = {
  entity_type: string;
  id: string;
  name: string;
  representative: StixRepresentative
};

export type StixRepresentative = {
  main: string;
};

export const allEntitiesKeyList = [
  'name',
  'aliases',
  'x_opencti_aliases',
  'x_mitre_id',
  'value',
  'subject',
  'attribute_abstract',
  'x_opencti_additional_names',
  // observables
  'iban',
  'hashes.MD5',
  'hashes.SHA-1',
  'hashes.SHA-256',
  'hashes.SHA-512',
  'url',
  'card_number',
  'value',
  'account_type',
  'user_id',
  'account_login',
  'path',
];

export const querySearchEntityByText = async (text: string) => {
  // TODO: see if representative can be use instead of this hardcoded list
  // TODO: if not get the list from backend instead of hardcoded here ?
  // This list can be find in backend in identifier.js stixBaseCyberObservableContribution.definition

  const searchPaginationOptions = {
    filters: {
      mode: 'and',
      filters: [
        {
          key: allEntitiesKeyList,
          values: [text],
        },
      ],
      filterGroups: [],
    },
    count: 1,
  };

  const result = await fetchQuery(
    searchStixCoreObjectsByRepresentativeQuery,
    searchPaginationOptions,
  ).toPromise()
    .then((data) => {
      return data;
    }) as StixCoreResultsType;
  return { ...result, searchTerm: text };
};
