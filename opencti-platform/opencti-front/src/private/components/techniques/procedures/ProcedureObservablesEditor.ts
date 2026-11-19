import { graphql } from 'react-relay';
import { commitMutation, fetchQuery } from '../../../../relay/environment';

// A procedure's observables are has-observable relationships (procedure → observable), not a ref of the procedure.
export const RELATION_HAS_OBSERVABLE = 'has-observable';

const procedureObservablesEditorAddMutation = graphql`
  mutation ProcedureObservablesEditorAddMutation($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id
    }
  }
`;

const procedureObservablesEditorDeleteMutation = graphql`
  mutation ProcedureObservablesEditorDeleteMutation($fromId: StixRef!, $toId: StixRef!, $relationship_type: String!) {
    stixCoreRelationshipDelete(fromId: $fromId, toId: $toId, relationship_type: $relationship_type)
  }
`;

// Reloads the procedure once the relationships changed, so the form and the overview show the new observables.
const procedureObservablesEditorRefreshQuery = graphql`
  query ProcedureObservablesEditorRefreshQuery($id: String!) {
    procedure(id: $id) {
      ...ProcedureEditionOverview_procedure
      ...Procedure_procedure
    }
  }
`;

const commit = (mutation: typeof procedureObservablesEditorAddMutation, variables: Record<string, unknown>) => new Promise<void>((resolve, reject) => {
  commitMutation({ mutation, variables, onCompleted: () => resolve(), onError: reject });
});

export const saveProcedureObservables = async (procedureId: string, { added, removed }: { added: string[]; removed: string[] }) => {
  if (added.length === 0 && removed.length === 0) return;
  await Promise.all([
    ...added.map((toId) => commit(procedureObservablesEditorAddMutation, {
      input: { fromId: procedureId, toId, relationship_type: RELATION_HAS_OBSERVABLE },
    })),
    ...removed.map((toId) => commit(procedureObservablesEditorDeleteMutation, {
      fromId: procedureId, toId, relationship_type: RELATION_HAS_OBSERVABLE,
    })),
  ]);
  await fetchQuery(procedureObservablesEditorRefreshQuery, { id: procedureId }, { fetchPolicy: 'network-only' }).toPromise();
};
