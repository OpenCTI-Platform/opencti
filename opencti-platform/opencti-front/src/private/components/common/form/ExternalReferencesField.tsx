import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { append } from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchQuery } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceCreationMutation$data } from '../../analyses/external_references/__generated__/ExternalReferenceCreationMutation.graphql';
import {
  ExternalReferencesQueriesSearchQuery$data,
  ExternalReferencesQueriesSearchQuery$variables,
} from '../../analyses/external_references/__generated__/ExternalReferencesQueriesSearchQuery.graphql';
import { externalReferenceLinesMutationRelationAdd } from '../../analyses/external_references/AddExternalReferencesLines';
import ExternalReferenceCreation from '../../analyses/external_references/ExternalReferenceCreation';
import { externalReferencesQueriesSearchQuery } from '../../analyses/external_references/ExternalReferencesQueries';
import { FieldOption } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  autoCompleteIndicator: {
    display: 'none',
  },
}));

export type ExternalReferencesValues = {
  label?: string;
  value: string;
  entity?: {
    created: string;
    description?: string | null;
    external_id?: string | null;
    id: string;
    source_name: string;
    url?: string | null;
  };
}[];

interface ExternalReferencesFieldProps {
  name: string;
  label?: string;
  style?: { marginTop: number; width: string };
  onChange?: (name: string, values: FieldOption[]) => void;
  setFieldValue: (
    field: string,
    value: {
      label?: string;
      value: string;
      entity?: {
        created: string;
        description?: string | null;
        external_id?: string | null;
        id: string;
        source_name: string;
        url?: string | null;
      };
    }[],
    shouldValidate?: boolean,
  ) => void;
  values?: ExternalReferencesValues;
  helpertext?: string;
  noStoreUpdate?: boolean;
  id?: string;
  dryrun?: boolean;
  required?:boolean;
  noCreation?: boolean; // Disable inline creation to avoid nested forms
}

export const ExternalReferencesField: FunctionComponent<
ExternalReferencesFieldProps
> = ({
  name,
  style,
  onChange,
  setFieldValue,
  values,
  helpertext,
  noStoreUpdate,
  id,
  dryrun,
  required = false,
  noCreation = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [externalReferenceCreation, setExternalReferenceCreation] = useState(false);
  const [externalReferences, setExternalReferences] = useState<
  {
    label?: string;
    value: string;
    entity?: {
      created?: string;
      description: string | null;
      external_id: string | null;
      id: string;
      source_name: string;
      url: string | null;
    };
  }[]
  >([]);

  const [commitExternalReference] = useApiMutation(externalReferenceLinesMutationRelationAdd);

  const handleOpenExternalReferenceCreation = () => {
    setExternalReferenceCreation(true);
  };

  const handleCloseExternalReferenceCreation = () => {
    setExternalReferenceCreation(false);
  };

  const searchExternalReferences = (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    let filters: ExternalReferencesQueriesSearchQuery$variables['filters'];
    if (id) {
      filters = {
        mode: 'and',
        filters: [{ key: ['externalReferences'], values: [id] }],
        filterGroups: [],
      };
    }
    fetchQuery(externalReferencesQueriesSearchQuery, {
      search: event && event.target.value,
      filters,
    })
      .toPromise()
      .then((data) => {
        const newExternalReferencesEdges = ((
          data as ExternalReferencesQueriesSearchQuery$data
        )?.externalReferences?.edges ?? []) as unknown as {
          node: {
            description: string | null;
            external_id: string | null;
            fileId: string | null;
            id: string;
            source_name: string;
            url: string | null;
          };
        }[];
        const newExternalReferences = newExternalReferencesEdges
          .slice()
          .sort((a, b) => a.node.source_name.localeCompare(b.node.source_name))
          .map((n) => ({
            label: `[${n.node.source_name}] ${truncate(
              n.node.description || n.node.url || n.node.external_id,
              150,
            )}`,
            value: n.node.id,
            entity: n.node,
          }));

        setExternalReferences(newExternalReferences);
      });
  };

  return (
    <>
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        required={required}
        multiple={true}
        filterOptions={(options: unknown) => (options)}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('External references'),
          helperText: helpertext,
          onFocus: searchExternalReferences,
          required,
        }}
        noOptionsText={t_i18n('No available options')}
        options={externalReferences}
        onInputChange={searchExternalReferences}
        openCreate={noCreation ? undefined : handleOpenExternalReferenceCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: FieldOption,
        ) => (
          <li {...props} key={option.value}>
            <div style={{
              paddingTop: 4,
              display: 'inline-block',
            }}
            >
              <ItemIcon type="External-Reference" />
            </div>
            <div style={{
              display: 'inline-block',
              flexGrow: 1,
              marginLeft: 10,
            }}
            >
              {option.label}
            </div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
      {!noCreation && (
        <ExternalReferenceCreation
          paginationOptions={undefined}
          contextual={true}
          display={true}
          openContextual={externalReferenceCreation}
          handleCloseContextual={handleCloseExternalReferenceCreation}
          dryrun={dryrun}
          creationCallback={(data: ExternalReferenceCreationMutation$data) => {
            const newExternalReference = data.externalReferenceAdd;
            if (id) {
              const input = {
                fromId: id,
                relationship_type: 'external-reference',
              };
              commitExternalReference({
                variables: {
                  id: newExternalReference?.id,
                  input,
                },
                updater: (store: RecordSourceSelectorProxy) => {
                  if (!noStoreUpdate) {
                    insertNode(
                      store,
                      'Pagination_externalReferences',
                      undefined,
                      'externalReferenceEdit',
                      id,
                      'relationAdd',
                      { input },
                      'to',
                    );
                  }
                },
              });
            }
            if (newExternalReference) {
              const externalReferenceLabel = `[${
                newExternalReference.source_name
              }] ${truncate(
                newExternalReference.description
                || newExternalReference.url
                || newExternalReference.external_id,
                150,
              )}`;
              const newExternalReferences = append(
                {
                  label: externalReferenceLabel,
                  value: newExternalReference.id,
                  entity: newExternalReference,
                },
                values || [],
              );
              setFieldValue(name, newExternalReferences ?? []);
            }
          }}
        />
      )}
    </>
  );
};
