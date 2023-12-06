import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useMutation, UseMutationConfig } from 'react-relay';
import { ObjectSchema, SchemaObjectDescription } from 'yup';
import { MutationParameters } from 'relay-runtime';
import { Option } from '@components/common/form/ReferenceField';
import { useFormatter } from 'src/components/i18n';
import { MESSAGING$ } from 'src/relay/environment';
import { convertAssignees, convertExternalReferences, convertKillChainPhases, convertMarkings, convertParticipants } from '../edition';
import useConfidenceLevel from './useConfidenceLevel';

export interface GenericData {
  id: string;
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
  const [commitRelationAdd] = useMutation(queries.relationAdd);
  const [commitRelationDelete] = useMutation(queries.relationDelete);
  const [commitFieldPatch] = useMutation(queries.fieldPatch);
  const [commitEditionFocus] = useMutation(queries.editionFocus);
  const schemaFields = (validator.describe() as SchemaObjectDescription).fields;
  const { t_i18n } = useFormatter();

  const handleToastUpdate = () => {
    MESSAGING$.notifySuccess(t_i18n('Relationship successfully edited'));
  };

  const validate = (
    name: string,
    values: number | number[] | string | Date | Option | Option[],
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
            onCompleted: handleToastUpdate,
          });
        }
        if (removed.length > 0) {
          commitRelationDelete({
            variables: {
              id: data.id,
              toId: removed[0].value,
              relationship_type: relation,
            },
            onCompleted: handleToastUpdate,
          });
        }
      });
    }
  };
  const changeMarking = (name: string, values: Option[], operation: string | undefined) => {
    if (operation === 'replace') {
      commitFieldPatch({
        variables: { id: data.id, input: [{ key: name, value: values.map((m) => m.value), operation }] },
        onCompleted: handleToastUpdate,
      });
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
          onCompleted: handleToastUpdate,
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
      onCompleted: handleToastUpdate,
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
          onCompleted: handleToastUpdate,
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
        onCompleted: handleToastUpdate,
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
