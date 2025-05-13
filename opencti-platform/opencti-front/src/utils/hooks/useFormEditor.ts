import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { UseMutationConfig } from 'react-relay';
import { ObjectSchema, SchemaObjectDescription } from 'yup';
import { MutationParameters } from 'relay-runtime';
import { Option } from '@components/common/form/ReferenceField';
import { convertAssignees, convertExternalReferences, convertKillChainPhases, convertMarkings, convertParticipants } from '../edition';
import useConfidenceLevel from './useConfidenceLevel';
import useApiMutation from './useApiMutation';

export interface GenericData {
  id: string;
  entity_type?: string;
  confidence?: number;
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
  validator: ObjectSchema<{ [p: string]: unknown }>,
) => {
  const [commitRelationAdd] = useApiMutation(queries.relationAdd);
  const [commitRelationDelete] = useApiMutation(queries.relationDelete);
  const [commitFieldPatch] = useApiMutation(queries.fieldPatch);
  const [commitEditionFocus] = useApiMutation(queries.editionFocus);
  const schemaFields = (validator.describe() as SchemaObjectDescription).fields;

  const validate = (
    name: string,
    values: number | number[] | string | Date | Option | Option[] | null,
    callback: () => void,
  ) => {
    if (schemaFields[name]) {
      validator
        .validateAt(name, { [name]: values })
        .then(() => {
          callback();
        })
        .catch(() => false);
    } else {
      callback();
    }
  };

  // Multiple
  const changeMultiple = (
    name: string,
    values: Option[],
    relation: string,
    optionMapper: (data: unknown) => [Option],
  ) => {
    if (!enableReferences) {
      validate(name, values, () => {
        const currentValues: [Option] = optionMapper(data);
        const added = values.filter(
          (v) => !currentValues.map((c) => c.value).includes(v.value),
        );
        const removed = currentValues.filter(
          (c) => !values.map((v) => v.value).includes(c.value),
        );
        if (added.length > 0) {
          commitRelationAdd({
            variables: {
              id: data.id,
              input: {
                toId: added[0].value,
                relationship_type: relation,
              },
            },
          });
        }
        if (removed.length > 0) {
          commitRelationDelete({
            variables: {
              id: data.id,
              toId: removed[0].value,
              relationship_type: relation,
            },
          });
        }
      });
    }
  };
  const changeMarking = (name: string, values: Option[], operation: string | undefined) => {
    if (operation === 'replace') {
      commitFieldPatch({ variables: { id: data.id, input: [{ key: name, value: values.map((m) => m.value), operation }] } });
    } else changeMultiple(name, values, 'object-marking', convertMarkings);
  };
  const changeAssignee = (name: string, values: Option[]) => {
    changeMultiple(name, values, 'object-assignee', convertAssignees);
  };
  const changeParticipant = (name: string, values: Option[]) => {
    changeMultiple(name, values, 'object-participant', convertParticipants);
  };
  const changeKillChainPhases = (name: string, values: Option[]) => {
    changeMultiple(name, values, 'kill-chain-phase', convertKillChainPhases);
  };
  const changeExternalReferences = (name: string, values: Option[]) => {
    changeMultiple(
      name,
      values,
      'external-reference',
      convertExternalReferences,
    );
  };

  // Simple
  const changeCreated = (name: string, value: Option | '') => {
    if (!enableReferences) {
      validate(name, value !== '' ? value : null, () => {
        const finalValue = value !== '' ? (value as Option).value : null;
        commitFieldPatch({
          variables: {
            id: data.id,
            input: [
              {
                key: 'createdBy',
                value: [finalValue],
              },
            ],
          },
        });
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
  const changeField = (name: string, value: number | number[] | string | Date | Option | Option[]) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      validate(name, value, () => {
        commitFieldPatch({
          variables: {
            id: data.id,
            input: [{ key: name, value: finalValue || '' }],
          },
        });
      });
    }
  };
  const changeGrantableGroups = (name: string, values: Option[]) => {
    validate(name, values, () => {
      const finalValues = values.map((v) => v.value);
      commitFieldPatch({
        variables: {
          id: data.id,
          input: [{ key: 'grantable_groups', value: finalValues }],
        },
      });
    });
  };

  const { checkConfidenceForEntity } = useConfidenceLevel();

  const checkAndCommitFieldPatch = (args: UseMutationConfig<MutationParameters>) => {
    if (!checkConfidenceForEntity(data, true)) return;
    commitFieldPatch(args);
  };

  const checkAndCommitChangeField = (name: string, value: number | number[] | string | Date | Option | Option[]) => {
    if (!checkConfidenceForEntity(data, true)) return;
    changeField(name, value);
  };

  return {
    changeMarking,
    changeAssignee,
    changeParticipant,
    changeCreated,
    changeKillChainPhases,
    changeExternalReferences,
    changeFocus,
    changeField: checkAndCommitChangeField,
    fieldPatch: checkAndCommitFieldPatch,
    changeGrantableGroups,
  };
};

export default useFormEditor;
