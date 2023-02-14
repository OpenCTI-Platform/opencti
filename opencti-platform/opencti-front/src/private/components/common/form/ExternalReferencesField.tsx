import React, { FunctionComponent, useState } from 'react';
import { append, union } from 'ramda';
import { Field } from 'formik';
import { LanguageOutlined } from '@mui/icons-material';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { externalReferencesQueriesSearchQuery } from '../../analysis/external_references/ExternalReferencesQueries';
import ExternalReferenceCreation from '../../analysis/external_references/ExternalReferenceCreation';
import { externalReferenceLinesMutationRelationAdd } from '../../analysis/external_references/AddExternalReferencesLines';
import { Option } from './ReferenceField';
import {
  ExternalReferencesQueriesSearchQuery$data,
  ExternalReferencesQueriesSearchQuery$variables,
} from '../../analysis/external_references/__generated__/ExternalReferencesQueriesSearchQuery.graphql';
import { ExternalReferenceCreationMutation$data } from '../../analysis/external_references/__generated__/ExternalReferenceCreationMutation.graphql';
import { insertNode } from '../../../../utils/store';

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
  onChange?: () => void;
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
    shouldValidate?: boolean
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
    let filters: ExternalReferencesQueriesSearchQuery$variables['filters'] = [];
    if (id) {
      filters = [{ key: ['usedBy'], values: [id] }];
    }
    fetchQuery(externalReferencesQueriesSearchQuery, {
      search: event && event.target.value,
      filters,
    })
      .toPromise()
      .then((data) => {
        const newExternalReferencesEdges = ((
          data as ExternalReferencesQueriesSearchQuery$data
        )?.externalReferences?.edges ?? []) as {
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
        setExternalReferences((o) => union(o, newExternalReferences));
      });
  };

  return (
    <div>
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
            <div className={classes.icon} style={{ color: option.color }}>
              <LanguageOutlined />
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
            setExternalReferences((o) => append(
              {
                label: `[${newExternalReference.source_name}] ${truncate(
                  newExternalReference.description
                      || newExternalReference.url
                      || newExternalReference.external_id,
                  150,
                )}`,
                value: newExternalReference.id,
                entity: newExternalReference,
              },
              o,
            ));
            setFieldValue(
              name,
              append(
                {
                  label: `[${newExternalReference.source_name}] ${truncate(
                    newExternalReference.description
                      || newExternalReference.url
                      || newExternalReference.external_id,
                    150,
                  )}`,
                  value: newExternalReference.id,
                  entity: newExternalReference,
                },
                values || [],
              ),
            );
          }
        }}
      />
    </div>
  );
};
