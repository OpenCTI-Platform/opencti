import React, { FunctionComponent, useState } from 'react';
import { union } from 'ramda';
import { Field } from 'formik';
import { CampaignOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import type { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import { triggersQueriesKnowledgeSearchQuery } from './TriggersQueries';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggerLiveCreation from './TriggerLiveCreation';
import { TriggerEventType, TriggerLiveCreationKnowledgeMutation$data } from './__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { TriggerType } from './__generated__/TriggerLine_node.graphql';
import { TriggersQueriesSearchKnowledgeQuery$data } from './__generated__/TriggersQueriesSearchKnowledgeQuery.graphql';
import { FieldOption } from '../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
}));

interface TriggersFieldProps {
  name: string;
  style?: { marginTop: number; width: string };
  onChange?: (
    name: string,
    value: {
      label?: string;
      value: string;
      entity?: { id: string; name: string };
    }[],
  ) => void;
  setFieldValue: (
    field: string,
    value: {
      label?: string;
      value: string;
      entity?: {
        id: string;
        name: string;
      };
    }[],
    shouldValidate?: boolean,
  ) => void;
  values: {
    label?: string;
    value: string;
    entity?: {
      id: string;
      name: string;
    };
  }[];
  helpertext?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  recipientId?: string;
}

const TriggersField: FunctionComponent<TriggersFieldProps> = ({
  name,
  style,
  onChange,
  setFieldValue,
  values,
  helpertext,
  paginationOptions,
  recipientId,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [triggerCreation, setTriggerCreation] = useState(false);
  const [triggers, setTriggers] = useState<
    {
      label?: string;
      value: string;
      entity?: {
        id: string;
        name: string;
      };
    }[]
  >([]);
  const handleOpenTriggerCreation = () => {
    setTriggerCreation(true);
  };
  const handleCloseTriggerCreation = () => {
    setTriggerCreation(false);
  };
  const searchTriggers = (search: string) => {
    const filtersContent = [{ key: 'trigger_type', values: ['live'] }];
    if (recipientId) {
      filtersContent.push({ key: 'authorized_members.id', values: [recipientId] });
    }
    fetchQuery(triggersQueriesKnowledgeSearchQuery, {
      search,
      includeAuthorities: !!recipientId,
      filters: {
        mode: 'and',
        filters: filtersContent,
        filterGroups: [],
      },
    })
      .toPromise()
      .then((data) => {
        const newTriggersEdges = ((data as TriggersQueriesSearchKnowledgeQuery$data)
          ?.triggersKnowledge?.edges ?? []) as {
          node: {
            created: string | null;
            description: string | null;
            event_types: Array<TriggerEventType>;
            id: string;
            modified: string | null;
            name: string;
            notifiers: Array<{ id: string }>;
            trigger_type: TriggerType;
          };
        }[];
        const newTriggers = newTriggersEdges
          .slice()
          .sort((a, b) => a.node.name.localeCompare(b.node.name))
          .map((n) => ({
            label: n.node.name,
            value: n.node.id,
            notifiers: n.node.notifiers.map(({ id }) => id),
            entity: n.node,
          }));
        setTriggers((o) => union(o, newTriggers));
      });
  };

  return (
    <div>
      <Field
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        style={style}
        name={name}
        multiple={true}
        label={t_i18n('Triggers')}
        helperText={helpertext}
        noOptionsText={t_i18n('No available options')}
        options={triggers}
        onInputChange={(search: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') searchTriggers(search);
        }}
        onFocusInput={() => searchTriggers('')}
        openCreate={handleOpenTriggerCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(option: FieldOption) => (
          <>
            <div className={classes.icon} style={{ color: option.color }}>
              <CampaignOutlined />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
      <TriggerLiveCreation
        contextual={true}
        open={triggerCreation}
        handleClose={handleCloseTriggerCreation}
        paginationOptions={paginationOptions}
        recipientId={recipientId}
        creationCallback={(data: TriggerLiveCreationKnowledgeMutation$data) => {
          const newTrigger = data.triggerKnowledgeLiveAdd;
          if (newTrigger) {
            const entity = { id: newTrigger.id, name: newTrigger.name };
            setTriggers((o) => [
              ...o,
              {
                label: newTrigger.name,
                value: newTrigger.id,
                entity,
              },
            ]);
            const newValues = [
              ...(values || []),
              {
                label: newTrigger.name,
                value: newTrigger.id,
                entity,
              },
            ];
            setFieldValue(name, newValues);
            if (typeof onChange === 'function') {
              onChange(name, newValues);
            }
          }
        }}
      />
    </div>
  );
};

export default TriggersField;
