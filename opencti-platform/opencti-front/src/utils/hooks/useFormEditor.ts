import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useMutation } from 'react-relay';
import { Option } from '../../private/components/common/form/ReferenceField';

interface GenericData {
  id: string;
  readonly objectMarking: {
    readonly edges: ReadonlyArray<{
      readonly node: {
        readonly definition: string | null;
        readonly definition_type: string | null;
        readonly id: string;
      };
    }>;
  } | null;
  readonly objectAssignee: {
    readonly edges: ReadonlyArray<{
      readonly node: {
        readonly entity_type: string;
        readonly id: string;
        readonly name: string;
      };
    }>;
  } | null;
}

interface Queries {
  fieldPatch: GraphQLTaggedNode;
  relationAdd: GraphQLTaggedNode;
  relationDelete: GraphQLTaggedNode;
  editionFocus: GraphQLTaggedNode;
}

const useFormEditor = (
  data: GenericData,
  enableReferences: boolean,
  queries: Queries,
) => {
  const [commitRelationAdd] = useMutation(queries.relationAdd);
  const [commitRelationDelete] = useMutation(queries.relationDelete);
  const [commitFieldPatch] = useMutation(queries.fieldPatch);
  const [commitEditionFocus] = useMutation(queries.editionFocus);
  const changeMarking = (name: string, values: Option[]) => {
    if (!enableReferences) {
      const currentMarkings = (data?.objectMarking?.edges ?? []).map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      }));
      const added = values.filter(
        (v) => !currentMarkings.map((c) => c.value).includes(v.value),
      );
      const removed = currentMarkings.filter(
        (c) => !values.map((v) => v.value).includes(c.value),
      );
      if (added.length > 0) {
        commitRelationAdd({
          variables: {
            id: data.id,
            input: {
              toId: added[0].value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitRelationDelete({
          variables: {
            id: data.id,
            toId: removed[0].value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const changeAssignee = (name: string, values: Option[]) => {
    if (!enableReferences) {
      const currentAssignees = (data?.objectAssignee?.edges ?? []).map((n) => ({
        label: n.node.name,
        value: n.node.id,
      }));
      const added = values.filter(
        (v) => !currentAssignees.map((c) => c.value).includes(v.value),
      );
      const removed = currentAssignees.filter(
        (c) => !values.map((v) => v.value).includes(c.value),
      );
      if (added.length > 0) {
        commitRelationAdd({
          variables: {
            id: data.id,
            input: {
              toId: added[0].value,
              relationship_type: 'object-assignee',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitRelationDelete({
          variables: {
            id: data.id,
            toId: removed[0].value,
            relationship_type: 'object-assignee',
          },
        });
      }
    }
  };

  const changeCreated = (name: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: data.id,
          input: [
            {
              key: 'createdBy',
              value: [value.value],
            },
          ],
        },
      });
    }
  };

  const changeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: data.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  return {
    changeMarking,
    changeAssignee,
    changeCreated,
    changeFocus,
    fieldPatch: commitFieldPatch,
  };
};

export default useFormEditor;
