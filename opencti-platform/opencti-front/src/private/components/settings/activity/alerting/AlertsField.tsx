import React, { FunctionComponent, ReactNode, useState } from 'react';
import { union } from 'ramda';
import { Field } from 'formik';
import { CampaignOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import { triggersQueriesActivitySearchQuery } from '../../../profile/triggers/TriggersQueries';
import { TriggersQueriesSearchActivityQuery$data } from '../../../profile/triggers/__generated__/TriggersQueriesSearchActivityQuery.graphql';
import { TriggerEventType } from '../../../profile/triggers/__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { TriggerType } from './__generated__/AlertingLine_node.graphql';
import AutocompleteField from '../../../../../components/AutocompleteField';
import AlertLiveCreation from './AlertLiveCreation';
import { AlertLiveCreationActivityMutation$data } from './__generated__/AlertLiveCreationActivityMutation.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';

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
  paginationOptions?: AlertingPaginationQuery$variables;
  required?: boolean;
}

interface Option {
  value: string;
  label: string;
  color?: string;
  [key: string]: ReactNode;
}

const AlertsField: FunctionComponent<TriggersFieldProps> = ({
  name,
  style,
  onChange,
  setFieldValue,
  values,
  helpertext,
  paginationOptions,
  required,
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
    const filters = {
      mode: 'and',
      filters: [{ key: 'trigger_type', values: ['live'] }],
      filterGroups: [],
    };
    fetchQuery(triggersQueriesActivitySearchQuery, { search: event && event.target.value, filters })
      .toPromise()
      .then((data) => {
        const newTriggersEdges = ((data as TriggersQueriesSearchActivityQuery$data)
          ?.triggersActivity?.edges ?? []) as {
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
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={triggers}
        onInputChange={searchTriggers}
        openCreate={handleOpenTriggerCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: Option,
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
      <AlertLiveCreation
        open={triggerCreation}
        handleClose={handleCloseTriggerCreation}
        paginationOptions={paginationOptions}
        creationCallback={(data: AlertLiveCreationActivityMutation$data) => {
          const newTrigger = data.triggerActivityLiveAdd;
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

export default AlertsField;
