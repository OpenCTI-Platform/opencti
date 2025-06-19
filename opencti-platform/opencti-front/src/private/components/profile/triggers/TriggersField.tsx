import React, { FunctionComponent, useState } from 'react';
import { union } from 'ramda';
import { Field } from 'formik';
import { CampaignOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
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
  autoCompleteIndicator: {
    display: 'none',
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
    }[]
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
    shouldValidate?: boolean
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
  const searchTriggers = (event: React.ChangeEvent<HTMLInputElement>) => {
    const filtersContent = [{ key: 'trigger_type', values: ['live'] }];
    if (recipientId) {
      filtersContent.push({ key: 'authorized_members.id', values: [recipientId] });
    }
    fetchQuery(triggersQueriesKnowledgeSearchQuery, {
      search: event && event.target.value,
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
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('Triggers'),
          helperText: helpertext,
          onFocus: searchTriggers,
        }}
        noOptionsText={t_i18n('No available options')}
        options={triggers}
        onInputChange={searchTriggers}
        openCreate={handleOpenTriggerCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: FieldOption,
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <CampaignOutlined />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
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
