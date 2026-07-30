import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import Button from '@mui/material/Button';
import { Field, Form, Formik, useFormikContext } from 'formik';
import * as Yup from 'yup';
import Drawer from '../../common/drawer/Drawer';
import TextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import Tag from '../../../../components/common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import PlaybookFlowFieldFilters from '../playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldFilters';
import PlaybookFlowFieldArray, { PlaybookFlowFieldArrayProps } from '../playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldArray';
import PlaybookFlowFieldBoolean from '../playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldBoolean';
import PlaybookFlowFieldOrganizations from '../playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldOrganizations';
import PlaybookFlowFieldAccessRestrictions from '../playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldAccessRestrictions';
import PlaybookFlowFieldActions from '../playbooks/playbookFlow/playbookFlowFields/playbookFlowFieldsActions/PlaybookFlowFieldActions';
import PlaybookFlowFieldCaseTemplates from '../playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldCaseTemplates';
import {
  serializeFilterGroupForBackend,
  deserializeFilterGroupForFrontend,
  emptyFilterGroup,
} from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { getDefinition, updateNodeConfig } from './preprocessingStore';
import { findComponent, CHANGE_ENTITY_TYPE_RULES, DEDUCT_MAIN_OBS_RULES } from './preprocessingComponents';

// ---- Static option sets ----

const CONTAINER_TYPE_OPTIONS: PlaybookFlowFieldArrayProps['options'] = [
  { const: 'Report', title: 'Report' },
  { const: 'Grouping', title: 'Grouping' },
  { const: 'Case-Incident', title: 'Incident Case' },
  { const: 'Case-Rfi', title: 'RFI Case' },
  { const: 'Case-Rft', title: 'RFT Case' },
  { const: 'Feedback', title: 'Feedback' },
  { const: 'Task', title: 'Task' },
];

const RULE_OPTIONS: PlaybookFlowFieldArrayProps['options'] = CHANGE_ENTITY_TYPE_RULES.map((r) => ({
  const: r.id,
  title: r.label,
}));

const DEDUCT_RULE_OPTIONS: PlaybookFlowFieldArrayProps['options'] = DEDUCT_MAIN_OBS_RULES.map((r) => ({
  const: r.id,
  title: r.label,
}));

// ---- Hook: fetch entity instances by type ----

interface EntityOption { value: string; label: string }

const useEntitiesByType = (entityType: string | null) => {
  const [options, setOptions] = useState<EntityOption[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!entityType) { setOptions([]); return; }
    setLoading(true);
    fetch('/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        query: `{ stixDomainObjects(types: ["${entityType}"], first: 500) { edges { node { id representative { main } } } } }`,
      }),
    })
      .then((r) => r.json())
      .then((data) => {
        const edges: { node: { id: string; representative?: { main: string } } }[] =
          data?.data?.stixDomainObjects?.edges ?? [];
        setOptions(edges.map((e) => ({ value: e.node.id, label: e.node.representative?.main ?? e.node.id })));
      })
      .catch(() => setOptions([]))
      .finally(() => setLoading(false));
  }, [entityType]);
  return { options, loading };
};

// ---- Change entity type sub-form ----

const ChangeEntityTypeFields: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<{ rule?: string; entityInstances?: string[] }>();
  const prevRule = useRef(values.rule);

  useEffect(() => {
    if (prevRule.current !== values.rule) {
      setFieldValue('entityInstances', []);
      prevRule.current = values.rule;
    }
  }, [values.rule, setFieldValue]);

  const selectedRule = CHANGE_ENTITY_TYPE_RULES.find((r) => r.id === values.rule);
  const { options, loading } = useEntitiesByType(selectedRule?.sourceType ?? null);

  return (
    <>
      <PlaybookFlowFieldArray name="rule" label={t_i18n('Rule to apply')} options={RULE_OPTIONS} required />
      <Field
        component={AutocompleteField}
        name="entityInstances"
        multiple
        disabled={!selectedRule || loading}
        style={fieldSpacingContainerStyle}
        textfieldprops={{
          variant: 'standard',
          label: loading ? t_i18n('Loading...') : t_i18n('Entity to be transformed'),
        }}
        options={options.map((o) => o.value)}
        getOptionLabel={(val: string) => options.find((o) => o.value === val)?.label ?? val}
        renderOption={(props: React.HTMLAttributes<HTMLLIElement>, val: string) => (
          <li {...props} key={val}>{options.find((o) => o.value === val)?.label ?? val}</li>
        )}
        renderTags={(vals: string[], getTagProps: (args: { index: number }) => object) =>
          vals.map((v, idx) => (
            <Tag
              {...getTagProps({ index: idx })}
              key={v}
              label={options.find((o) => o.value === v)?.label ?? v}
            />
          ))
        }
      />
    </>
  );
};

// ---- Props & main component ----

interface PreprocessingNodeConfigProps {
  ruleId: string;
  nodeId: string | null;
  onClose: () => void;
  onSaved?: () => void;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyRecord = Record<string, any>;

const PreprocessingNodeConfigInner: FunctionComponent<PreprocessingNodeConfigProps> = ({
  ruleId, nodeId, onClose, onSaved,
}) => {
  const { t_i18n } = useFormatter();

  const node = nodeId ? getDefinition(ruleId).nodes.find((n) => n.id === nodeId) : undefined;
  const comp = node ? findComponent(node.componentId) : undefined;
  const existingConfig: AnyRecord = node?.configuration ? JSON.parse(node.configuration) : {};
  const cId = comp?.id ?? '';

  const hasStreamFilter = ['LISTEN_INGESTION', 'MATCH_KNOWLEDGE'].includes(cId);

  const filtersState = useFiltersState(
    existingConfig.filters ? deserializeFilterGroupForFrontend(existingConfig.filters) : emptyFilterGroup,
  );

  const validation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const initialValues = {
    name: node?.name ?? comp?.name ?? '',
    description: node?.description ?? '',
    // Match Knowledge
    all: existingConfig.all ?? false,
    // Container wrapper
    container_type: existingConfig.container_type ?? '',
    caseTemplates: existingConfig.caseTemplates ?? [],
    copyFiles: existingConfig.copyFiles ?? false,
    newContainer: existingConfig.newContainer ?? false,
    // Extract / Promote
    wrap_in_container: existingConfig.wrap_in_container ?? false,
    types: existingConfig.types ?? [],
    // Organizations
    organizations: existingConfig.organizations ?? [],
    // Access restrictions
    access_restrictions: existingConfig.access_restrictions ?? [],
    // Actions (manipulate knowledge)
    actions: existingConfig.actions ?? [],
    actionsFormValues: existingConfig.actionsFormValues ?? [],
    // Change entity type
    rule: existingConfig.rule ?? '',
    entityInstances: existingConfig.entityInstances ?? [],
    // Deduct main obs
    complexIocRule: existingConfig.complexIocRule ?? '',
  };

  const handleSubmit = (
    values: typeof initialValues,
    { setSubmitting }: { setSubmitting: (b: boolean) => void },
  ) => {
    const { name, description, actionsFormValues, ...configFields } = values;
    const config: AnyRecord = { ...configFields };
    if (hasStreamFilter) config.filters = serializeFilterGroupForBackend(filtersState[0]);
    if (nodeId) updateNodeConfig(ruleId, nodeId, name, description.trim() || comp?.description || name, JSON.stringify(config));    setSubmitting(false);
    onSaved?.();
    onClose();
  };

  const drawerTitle = t_i18n('Update component: {component_name}', {
    values: { component_name: comp ? t_i18n(comp.name) : '' },
  });

  return (
    <Drawer title={drawerTitle} open={nodeId !== null} onClose={onClose}>
      {({ onClose: innerOnClose }) => (
        <Formik
          key={nodeId ?? 'none'}
          initialValues={initialValues}
          validationSchema={validation}
          onSubmit={handleSubmit}
          onReset={innerOnClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ padding: '8px 0' }}>
              <Field component={TextField} variant="standard" name="name" label={t_i18n('Name')} fullWidth />
              <Field component={TextField} variant="standard" name="description" label={t_i18n('Description')} multiline style={fieldSpacingContainerStyle} fullWidth />

              {/* LISTEN_INGESTION / MATCH_KNOWLEDGE — filters */}
              {hasStreamFilter && (
                <PlaybookFlowFieldFilters componentId={cId} filtersState={filtersState} />
              )}

              {/* MATCH_KNOWLEDGE — all elements toggle */}
              {cId === 'MATCH_KNOWLEDGE' && (
                <PlaybookFlowFieldBoolean name="all" label={t_i18n('Match on any elements included in the bundle')} />
              )}

              {/* CHANGE_ENTITY_TYPE */}
              {cId === 'CHANGE_ENTITY_TYPE' && <ChangeEntityTypeFields />}

              {/* DEDUCT_MAIN_OBS */}
              {cId === 'DEDUCT_MAIN_OBS' && (
                <PlaybookFlowFieldArray
                  name="complexIocRule"
                  label={t_i18n('Rule to apply for complex IOC (AND/OR in the pattern)')}
                  options={DEDUCT_RULE_OPTIONS}
                  required
                />
              )}

              {/* CONTAINER_WRAPPER */}
              {cId === 'CONTAINER_WRAPPER' && (
                <>
                  <PlaybookFlowFieldArray name="container_type" label={t_i18n('Container type')} options={CONTAINER_TYPE_OPTIONS} required />
                  <PlaybookFlowFieldCaseTemplates />
                  <PlaybookFlowFieldBoolean name="copyFiles" label={t_i18n('Copy files from main element to the container')} />
                  <PlaybookFlowFieldBoolean name="newContainer" label={t_i18n('Create a new container at each run')} />
                </>
              )}

              {/* EXTRACT_OBSERVABLE */}
              {cId === 'EXTRACT_OBSERVABLE' && (
                <PlaybookFlowFieldBoolean name="wrap_in_container" label={t_i18n('If main entity is a container, wrap observables in container')} />
              )}

              {/* PROMOTE_IOC */}
              {cId === 'PROMOTE_IOC' && (
                <PlaybookFlowFieldBoolean name="wrap_in_container" label={t_i18n('If main entity is a container, wrap indicators in container')} />
              )}

              {/* MANIPULATE_KNOWLEDGE */}
              {cId === 'MANIPULATE_KNOWLEDGE' && (
                <PlaybookFlowFieldActions operations={['add', 'replace', 'remove']} />
              )}

              {/* MANAGE_ACCESS_RESTRICTION */}
              {cId === 'MANAGE_ACCESS_RESTRICTION' && <PlaybookFlowFieldAccessRestrictions />}

              {/* SHARE_TO_ORG / UNSHARE_FROM_ORG */}
              {(cId === 'SHARE_TO_ORG' || cId === 'UNSHARE_FROM_ORG') && <PlaybookFlowFieldOrganizations />}

              <FormButtonContainer>
                <Button variant="outlined" onClick={handleReset} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
                <Button variant="contained" color="secondary" onClick={submitForm} disabled={isSubmitting}>{t_i18n('Save')}</Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

const PreprocessingNodeConfig: FunctionComponent<PreprocessingNodeConfigProps> = (props) => (
  <PreprocessingNodeConfigInner key={props.nodeId ?? 'none'} {...props} />
);

export default PreprocessingNodeConfig;