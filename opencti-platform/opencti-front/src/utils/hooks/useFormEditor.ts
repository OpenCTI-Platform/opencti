import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useMutation } from 'react-relay';
import BaseSchema, { SchemaObjectDescription } from 'yup/lib/schema';
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
  readonly objectAssignee?: {
    readonly edges: ReadonlyArray<{
      readonly node: {
        readonly entity_type: string;
        readonly id: string;
        readonly name: string;
      };
    }>;
  } | null;
  readonly killChainPhases?: {
    readonly edges: ReadonlyArray<{
      readonly node: {
        readonly id: string;
        readonly kill_chain_name: string;
        readonly phase_name: string;
        readonly x_opencti_order: number | null;
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
  validator: BaseSchema,
) => {
  const [commitRelationAdd] = useMutation(queries.relationAdd);
  const [commitRelationDelete] = useMutation(queries.relationDelete);
  const [commitFieldPatch] = useMutation(queries.fieldPatch);
  const [commitEditionFocus] = useMutation(queries.editionFocus);
  const schemaFields = (validator.describe() as SchemaObjectDescription).fields;

  const validate = (name: string, values: Option[] | Option, callback: () => void) => {
    if (schemaFields[name]) {
      validator.validateAt(name, { [name]: values })
        .then(() => {
          callback();
        })
        .catch(() => false);
    } else {
      callback();
    }
  };

  const changeMarking = (name: string, values: Option[]) => {
    if (!enableReferences) {
      validate(name, values, () => {
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
      });
    }
  };

  const changeAssignee = (name: string, values: Option[]) => {
    if (!enableReferences) {
      validate(name, values, () => {
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
      });
    }
  };

  const changeCreated = (name: string, value: Option) => {
    if (!enableReferences) {
      validate(name, value, () => {
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
      });
    }
  };

  const changeKillChainPhases = (name: string, values: Option[]) => {
    if (!enableReferences) {
      validate(name, values, () => {
        const currentKillChainPhases = (data.killChainPhases?.edges ?? []).map((n) => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        }));
        const added = values.filter(
          (v) => !currentKillChainPhases.map((c) => c.value).includes(v.value),
        );
        const removed = currentKillChainPhases.filter(
          (c) => !values.map((v) => v.value).includes(c.value),
        );
        if (added.length > 0) {
          commitRelationAdd({
            variables: {
              id: data.id,
              input: {
                toId: added[0].value,
                relationship_type: 'kill-chain-phase',
              },
            },
          });
        }
        if (removed.length > 0) {
          commitRelationDelete({
            variables: {
              id: data.id,
              toId: removed[0].value,
              relationship_type: 'kill-chain-phase',
            },
          });
        }
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
    changeKillChainPhases,
    changeFocus,
    fieldPatch: commitFieldPatch,
  };
};

export default useFormEditor;
