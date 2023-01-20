import React, { FunctionComponent, ReactNode, useState } from 'react';
import { union } from 'ramda';
import { Field } from 'formik';
import { CampaignOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import {
  TriggerEventType,
  TriggersQueriesSearchQuery$data,
  TriggerType,
} from './__generated__/TriggersQueriesSearchQuery.graphql';
import { triggersQueriesSearchQuery } from './TriggersQueries';
import { TriggerCreationLiveMutation$data } from './__generated__/TriggerCreationLiveMutation.graphql';
import TriggerLiveCreation from './TriggerLiveCreation';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';

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
}

interface Option {
  value: string;
  label: string;
  color?: string;
  [key: string]: ReactNode;
}

const TriggersField: FunctionComponent<TriggersFieldProps> = ({
  name,
  style,
  onChange,
  setFieldValue,
  values,
  helpertext,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
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
    fetchQuery(triggersQueriesSearchQuery, {
      search: event && event.target.value,
      filters: [{ key: 'trigger_type', values: ['live'] }],
    })
      .toPromise()
      .then((data) => {
        const newTriggersEdges = ((data as TriggersQueriesSearchQuery$data)
          ?.myTriggers?.edges ?? []) as {
          node: {
            created: string | null;
            description: string | null;
            event_types: Array<TriggerEventType>;
            id: string;
            modified: string | null;
            name: string;
            outcomes: Array<string>;
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
          label: t('Triggers'),
          helperText: helpertext,
          onFocus: searchTriggers,
        }}
        noOptionsText={t('No available options')}
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
      <TriggerLiveCreation
        contextual={true}
        hideSpeedDial={true}
        open={triggerCreation}
        handleClose={handleCloseTriggerCreation}
        paginationOptions={paginationOptions}
        creationCallback={(data: TriggerCreationLiveMutation$data) => {
          const newTrigger = data.triggerLiveAdd;
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
