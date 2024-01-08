import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { append, union, take } from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
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
import { Option } from './ReferenceField';

const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

export type ExternalReferencesValues = {
  label?: string;
  value: string;
  entity?: {
    created: string;
    description: string | null;
    external_id: string | null;
    id: string;
    source_name: string;
    url: string | null;
  };
}[];

interface ExternalReferencesFieldProps {
  name: string;
  style?: { marginTop: number; width: string };
  onChange?: (name: string, values: Option[]) => void;
  setFieldValue: (
    field: string,
    value: {
      label?: string;
      value: string;
      entity?: {
        created: string;
        description: string | null;
        external_id: string | null;
        id: string;
        source_name: string;
        url: string | null;
      };
    }[],
    shouldValidate?: boolean,
  ) => void;
  values?: ExternalReferencesValues;
  helpertext?: string;
  noStoreUpdate?: boolean;
  id?: string;
  dryrun?: boolean;
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
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

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
        setExternalReferences((o) => union(take(50, o), newExternalReferences));
      });
  };

  return (
    <>
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t('External references'),
          helperText: helpertext,
          onFocus: searchExternalReferences,
        }}
        noOptionsText={t('No available options')}
        options={externalReferences}
        onInputChange={searchExternalReferences}
        openCreate={handleOpenExternalReferenceCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: Option,
        ) => (
          <li {...props}>
            <div className={classes.icon}>
              <ItemIcon type="External-Reference" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
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
            commitMutation({
              mutation: externalReferenceLinesMutationRelationAdd,
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
                    input,
                    'to',
                  );
                }
              },
              optimisticUpdater: undefined,
              optimisticResponse: undefined,
              onCompleted: undefined,
              onError: undefined,
              setSubmitting: undefined,
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
            setFieldValue(name, newExternalReferences);
          }
        }}
      />
    </>
  );
};
