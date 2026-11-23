import { graphql } from 'react-relay';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import type { ComponentObservable } from './ProcedureComponentsField';
import type { ProcedureComponentsEditorSearchQuery$data } from './__generated__/ProcedureComponentsEditorSearchQuery.graphql';
import type { ProcedureComponentsEditorTextAddMutation$data } from './__generated__/ProcedureComponentsEditorTextAddMutation.graphql';

const procedureComponentsEditorSetMutation = graphql`
  mutation ProcedureComponentsEditorSetMutation($id: ID!, $components: [ProcedureComponentInput!]!) {
    procedureComponentsSet(id: $id, components: $components) {
      id
      ...ProcedureComponents_procedure
      ...ProcedureEditionOverview_procedure
    }
  }
`;

const procedureComponentsEditorTextAddMutation = graphql`
  mutation ProcedureComponentsEditorTextAddMutation($value: String!) {
    stixCyberObservableAdd(type: "Text", Text: { value: $value }) {
      id
      entity_type
      observable_value
    }
  }
`;

const procedureComponentsEditorSearchQuery = graphql`
  query ProcedureComponentsEditorSearchQuery($search: String) {
    stixCyberObservables(search: $search, first: 50) {
      edges {
        node {
          id
          entity_type
          observable_value
        }
      }
    }
  }
`;

// Saves go one after the other, so a quick second change never lands before the first: the last order wins.
let pendingSave: Promise<void> = Promise.resolve();

export const saveProcedureComponents = (procedureId: string, components: { id: string; type: string }[]) => {
  const save = () => new Promise<void>((resolve, reject) => {
    commitMutation({
      mutation: procedureComponentsEditorSetMutation,
      variables: { id: procedureId, components },
      onCompleted: () => resolve(),
      onError: reject,
    });
  });
  pendingSave = pendingSave.catch(() => undefined).then(save);
  return pendingSave;
};

export const createTextObservable = (value: string) => new Promise<ComponentObservable>((resolve, reject) => {
  commitMutation({
    mutation: procedureComponentsEditorTextAddMutation,
    variables: { value },
    onCompleted: (response: ProcedureComponentsEditorTextAddMutation$data) => {
      const created = response.stixCyberObservableAdd;
      if (created) resolve({ id: created.id, entity_type: created.entity_type, observable_value: created.observable_value });
      else reject(new Error('The Text observable was not created'));
    },
    onError: reject,
  });
});

export const searchObservables = async (search: string): Promise<ComponentObservable[]> => {
  const data = await fetchQuery(procedureComponentsEditorSearchQuery, { search }).toPromise() as ProcedureComponentsEditorSearchQuery$data;
  return (data?.stixCyberObservables?.edges ?? [])
    .flatMap((edge) => (edge?.node ? [{ id: edge.node.id, entity_type: edge.node.entity_type, observable_value: edge.node.observable_value }] : []));
};
