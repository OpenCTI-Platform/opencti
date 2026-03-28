import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import ObservableTypesField from '@components/common/form/ObservableTypesField';
import { AddOutlined, Delete } from '@mui/icons-material';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { Field, FieldArray, Form, Formik, FormikConfig } from 'formik';
import { InformationOutline } from 'mdi-material-ui';
import * as R from 'ramda';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import TextField from '../../../../components/TextField';
import FormButtonContainer from '@common/form/FormButtonContainer';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../utils/store';
import decayRuleValidator from './DecayRuleValidator';
import { DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';
import DecayRuleCreationForm from './DecayRuleCreationForm';

interface DecayRuleCreationFormData {
  name: string;
  description: string;
  order: number;
  active: boolean;
  decay_lifetime: number;
  decay_pound: number;
  decay_points: number[];
  decay_revoke_score: number;
  decay_filters: string;
}

interface DecayRuleCreationProps {
  paginationOptions: DecayRulesLinesPaginationQuery$variables;
}

const CreateDecayRuleControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="DecayRule"
    {...props}
  />
);

const DecayRuleCreation = ({ paginationOptions }: DecayRuleCreationProps) => {
  const { t_i18n } = useFormatter();

  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_decayRules',
      paginationOptions,
      rootField,
    );
  };

  return (
    <Drawer
      title={t_i18n('Create a decay rule')}
      controlledDial={CreateDecayRuleControlledDial}
    >
      {({ onClose }) => (
        <DecayRuleCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default DecayRuleCreation;
