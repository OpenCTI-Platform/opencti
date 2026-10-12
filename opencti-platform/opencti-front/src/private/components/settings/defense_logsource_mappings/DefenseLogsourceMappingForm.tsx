import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { Box, Stack, Typography } from '@mui/material';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Input,
  Switch,
  Textarea,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { notifyPayloadErrors } from '../../defense/matrix/defenseMutation-utils';
import { DefenseLogsourceMappingFormSearchQuery$data } from './__generated__/DefenseLogsourceMappingFormSearchQuery.graphql';
import { DefenseLogsourceMappingFormAddMutation } from './__generated__/DefenseLogsourceMappingFormAddMutation.graphql';
import { DefenseLogsourceMappingFormPatchMutation } from './__generated__/DefenseLogsourceMappingFormPatchMutation.graphql';

const defenseLogsourceMappingFormSearchQuery = graphql`
  query DefenseLogsourceMappingFormSearchQuery($search: String) {
    dataComponents(search: $search, first: 50, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const defenseLogsourceMappingFormAddMutation = graphql`
  mutation DefenseLogsourceMappingFormAddMutation($input: DefenseLogsourceMappingAddInput!) {
    defenseLogsourceMappingAdd(input: $input) {
      id
    }
  }
`;

const defenseLogsourceMappingFormPatchMutation = graphql`
  mutation DefenseLogsourceMappingFormPatchMutation($id: ID!, $input: [EditInput!]!) {
    defenseLogsourceMappingFieldPatch(id: $id, input: $input) {
      id
      description
      data_components
      active
    }
  }
`;

export interface DefenseLogsourceMappingFormData {
  id: string;
  name: string;
  logsource_category?: string | null;
  logsource_product?: string | null;
  logsource_service?: string | null;
  data_components: ReadonlyArray<string>;
  description?: string | null;
  active: boolean;
  built_in: boolean;
}

interface NameOption {
  value: string;
  label: string;
}

interface DefenseLogsourceMappingFormProps {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
  // The edited mapping, a creation when omitted
  mapping?: DefenseLogsourceMappingFormData | null;
}

const toOption = (name: string): NameOption => ({ value: name, label: name });

const DefenseLogsourceMappingForm = ({ open, onClose, onSaved, mapping }: DefenseLogsourceMappingFormProps) => {
  const { t_i18n } = useFormatter();
  const isEdition = !!mapping;
  const [category, setCategory] = useState('');
  const [product, setProduct] = useState('');
  const [service, setService] = useState('');
  const [dataComponents, setDataComponents] = useState<NameOption[]>([]);
  const [description, setDescription] = useState('');
  const [active, setActive] = useState(true);
  const [options, setOptions] = useState<NameOption[]>([]);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const requestId = useRef(0);
  const [commitAdd, adding] = useApiMutation<DefenseLogsourceMappingFormAddMutation>(defenseLogsourceMappingFormAddMutation);
  const [commitPatch, patching] = useApiMutation<DefenseLogsourceMappingFormPatchMutation>(defenseLogsourceMappingFormPatchMutation);

  useEffect(() => {
    if (!open) return;
    setCategory(mapping?.logsource_category ?? '');
    setProduct(mapping?.logsource_product ?? '');
    setService(mapping?.logsource_service ?? '');
    setDataComponents((mapping?.data_components ?? []).map(toOption));
    setDescription(mapping?.description ?? '');
    setActive(mapping?.active ?? true);
  }, [open, mapping?.id]);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const search = (input: string) => {
    if (timer.current) clearTimeout(timer.current);
    // Only the response to the latest input may replace the options
    requestId.current += 1;
    const current = requestId.current;
    timer.current = setTimeout(() => {
      fetchQuery(defenseLogsourceMappingFormSearchQuery, { search: input })
        .toPromise()
        .then((data) => {
          if (current !== requestId.current) return;
          const edges = (data as DefenseLogsourceMappingFormSearchQuery$data | undefined)?.dataComponents?.edges ?? [];
          setOptions(edges.flatMap((edge) => (edge?.node ? [toOption(edge.node.name)] : [])));
        })
        .catch(() => {
          // Options of an earlier input are never shown as the results of a failed search
          if (current === requestId.current) setOptions([]);
        });
    }, 300);
  };

  const hasLogsource = category.trim() || product.trim() || service.trim();
  const valid = dataComponents.length > 0 && (isEdition || hasLogsource);
  const names = dataComponents.map((o) => o.value);

  const submit = () => {
    if (!valid) return;
    if (mapping) {
      commitPatch({
        variables: {
          id: mapping.id,
          input: [
            { key: 'data_components', value: names },
            { key: 'description', value: [description] },
            { key: 'active', value: [active] },
          ],
        },
        onCompleted: (response, errors) => {
          if (notifyPayloadErrors(errors) || !response.defenseLogsourceMappingFieldPatch) return;
          MESSAGING$.notifySuccess(t_i18n('Telemetry mapping updated'));
          onSaved();
          onClose();
        },
      });
      return;
    }
    commitAdd({
      variables: {
        input: {
          logsource_category: category.trim() || null,
          logsource_product: product.trim() || null,
          logsource_service: service.trim() || null,
          data_components: names,
          description: description.trim() || null,
          active,
        },
      },
      onCompleted: (response, errors) => {
        if (notifyPayloadErrors(errors) || !response.defenseLogsourceMappingAdd) return;
        MESSAGING$.notifySuccess(t_i18n('Telemetry mapping created'));
        onSaved();
        onClose();
      },
    });
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={isEdition ? t_i18n('Update a telemetry mapping') : t_i18n('Add a mapping')}
    >
      <Stack spacing={2.5} data-testid="defense-logsource-mapping-form">
        <Typography variant="body2" color="text.secondary">
          {t_i18n('A mapping says which MITRE data source a log source feeds. It applies to every log source matching all the fields you fill in.')}
        </Typography>
        <Typography variant="h4">{t_i18n('Log source')}</Typography>
        <Input
          label={t_i18n('Log source category')}
          value={category}
          disabled={isEdition}
          onChange={(e) => setCategory(e.target.value)}
          placeholder="process_creation"
          helperText={t_i18n('What the events describe, for example process_creation')}
          data-testid="defense-logsource-mapping-category"
        />
        <Input
          label={t_i18n('Log source product')}
          value={product}
          disabled={isEdition}
          onChange={(e) => setProduct(e.target.value)}
          placeholder="windows"
          helperText={t_i18n('The system the events come from, for example windows')}
          data-testid="defense-logsource-mapping-product"
        />
        <Input
          label={t_i18n('Log source service')}
          value={service}
          disabled={isEdition}
          onChange={(e) => setService(e.target.value)}
          placeholder="sysmon"
          helperText={t_i18n('The tool or channel that collects them, for example sysmon')}
          data-testid="defense-logsource-mapping-service"
        />
        <Typography variant="h4">{t_i18n('Data source')}</Typography>
        <Combobox<NameOption>
          multiple
          className="w-full"
          options={options}
          value={dataComponents}
          getOptionLabel={(o) => o.label}
          isOptionEqualToValue={(a, b) => a.value.toLowerCase() === b.value.toLowerCase()}
          filterOptions={(all) => all}
          allowCustomValue
          createValueFromInput={(input) => toOption(input.trim())}
          onInputChange={(input) => search(input)}
          onOpenChange={(isOpen) => {
            if (isOpen && options.length === 0) search('');
          }}
          onValueChange={(next) => setDataComponents(((next as NameOption[] | null) ?? []).filter((o) => o.value.length > 0))}
          required
        >
          <ComboboxLabel>{t_i18n('Data components')}</ComboboxLabel>
          <ComboboxField>
            <ComboboxChips aria-label={t_i18n('Data components')} />
            <ComboboxInput data-testid="defense-logsource-mapping-data-components" />
            <ComboboxControls>
              <ComboboxClear />
              <ComboboxTrigger />
            </ComboboxControls>
          </ComboboxField>
          <ComboboxHelperText>{t_i18n('The MITRE ATT&CK data components these events provide, for example Process Creation')}</ComboboxHelperText>
          <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={t_i18n('Data components')} />
        </Combobox>
        <Textarea
          label={t_i18n('Description')}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <Switch label={t_i18n('Active')} checked={active} onCheckedChange={setActive} />
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
          <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
          <Button onClick={submit} disabled={!valid || adding || patching} data-testid="defense-logsource-mapping-submit">
            {isEdition ? t_i18n('Update') : t_i18n('Create')}
          </Button>
        </Box>
      </Stack>
    </Drawer>
  );
};

export default DefenseLogsourceMappingForm;
