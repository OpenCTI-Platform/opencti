import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import React, { useEffect, useMemo, useState } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import {
  InvestigationExpandFormTypesQuery$data,
} from '@components/workspaces/investigations/__generated__/InvestigationExpandFormTypesQuery.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SwitchField from '../../../../components/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import {
  InvestigationExpandFormTargetsDistributionQuery$data,
} from './__generated__/InvestigationExpandFormTargetsDistributionQuery.graphql';
import CheckboxesField from '../../../../components/CheckboxesField';

// The number of elements targeted by or targeting the given
// entities ids, sorted by type of entity.
const investigationExpandFormTargetsDistributionQuery = graphql`
  query InvestigationExpandFormTargetsDistributionQuery($ids: [String]) {
    stixRelationshipsDistribution(
      elementId: $ids
      operation: count
      field: "entity_type"
      relationship_type: "stix-relationship"
    ) {
      label
      value
    }
  }
`;

const investigationExpandFormTypesQuery = graphql`
  query InvestigationExpandFormTypesQuery {
    stixCoreRelationshipTypes: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixNestedRefRelationshipTypes: subTypes(type: "stix-nested-ref-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

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

type FormData = {
  entity_types: SelectOption[],
  relationship_types: SelectOption[],
  reset_filters: boolean,
};

type SelectOption = {
  label: string
  value: string
};

type Props = {
  links: {
    source: {
      id: string
      entity_type: string
      [key:string]: unknown
    }
    target: {
      id: string
      entity_type: string
      [key:string]: unknown
    }
    [key:string]: unknown
  }[]
  selectedNodes: {
    id: string
    [key:string]: unknown
  }[]
  onSubmit: (data: FormData, helpers: FormikHelpers<FormData>) => void
  onReset: () => void
};

export default function InvestigationExpandForm({
  links,
  selectedNodes,
  onSubmit,
  onReset,
}: Props) {
  const classes = useStyles();
  const { t } = useFormatter();
  const [targets, setTargets] = useState<SelectOption[]>([]);
  const [relationships, setRelationships] = useState<SelectOption[]>([]);

  // How many entity types we already have in the graph.
  const existingTargets = useMemo(() => {
    const countTargets = new Map<string, Map<string, number>>();

    links.forEach((link) => {
      const from = link.source.id;
      const to = link.target.id;
      if (!countTargets.has(from)) {
        countTargets.set(from, new Map());
      }
      if (!countTargets.has(to)) {
        countTargets.set(to, new Map());
      }

      const typeFrom = link.target.entity_type;
      const targetFrom = countTargets.get(from);
      if (targetFrom) {
        const current = targetFrom?.get(typeFrom);
        if (current !== undefined) {
          targetFrom.set(typeFrom, current + 1);
        } else {
          targetFrom.set(typeFrom, 1);
        }
      }

      const typeTo = link.source.entity_type;
      const targetTo = countTargets.get(to);
      if (targetTo) {
        const current = targetTo?.get(typeTo);
        if (current !== undefined) {
          targetTo.set(typeTo, current + 1);
        } else {
          targetTo.set(typeTo, 1);
        }
      }
    });

    return countTargets;
  }, [links]);

  // Fetch all possible targets connected to the node to expand.
  useEffect(() => {
    async function fetchTargets() {
      if (selectedNodes.length === 0) return;
      const nodeIds = Array.from(selectedNodes).map((node) => node.id);

      const { stixRelationshipsDistribution } = await fetchQuery(
        investigationExpandFormTargetsDistributionQuery,
        { ids: nodeIds },
      ).toPromise() as InvestigationExpandFormTargetsDistributionQuery$data;

      const existingTargetsSelected = new Map<string, number>();
      nodeIds.forEach((node) => {
        const nodeTargets = existingTargets.get(node);
        if (nodeTargets) {
          nodeTargets.forEach((value, key) => {
            const current = existingTargetsSelected.get(key);
            if (current !== undefined) {
              existingTargetsSelected.set(key, current + value);
            } else {
              existingTargetsSelected.set(key, value);
            }
          });
        }
      });

      const nonNullDistribution = (stixRelationshipsDistribution ?? [])
        // Use of flatMap() to do both filter() and map() in one step.
        .flatMap((target) => (target ? [{
          label: target.label,
          // Decrease from the count of already displayed elements.
          value: (target.value ?? 0) - (existingTargetsSelected.get(target.label) ?? 0),
        }] : []))
        // Remove from the list entities with nothing to add.
        .filter(({ value }) => value > 0)
        .sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

      setTargets(
        nonNullDistribution
          .map(({ label, value }) => ({
            label: `${label} (${value})`,
            value: label,
          })),
      );
    }
    fetchTargets();
  }, [selectedNodes, existingTargets, setTargets]);

  async function searchTypes() {
    const {
      stixCoreRelationshipTypes,
      stixNestedRefRelationshipTypes,
    } = await fetchQuery(investigationExpandFormTypesQuery)
      .toPromise() as InvestigationExpandFormTypesQuery$data;

    setRelationships(
      [
        ...stixCoreRelationshipTypes.edges.map((edge) => ({
          label: edge.node.label,
          value: edge.node.label,
        })),
        ...stixNestedRefRelationshipTypes.edges.map((edge) => ({
          label: edge.node.label,
          value: edge.node.label,
        })),
      ],
    );
  }

  // JSX for an item of Select field.
  function renderSelectOption(props: object, option: SelectOption) {
    return (
      <li {...props}>
        <div className={classes.icon}>
          <ItemIcon type={option.value} />
        </div>
        <div className={classes.text}>{option.label}</div>
      </li>
    );
  }

  return (
    <Formik<FormData>
      enableReinitialize={true}
      initialValues={{
        entity_types: [],
        relationship_types: [],
        reset_filters: true,
      }}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <DialogTitle>{t('Expand elements')}</DialogTitle>
          <DialogContent>
            <Field
              name="entity_types"
              component={CheckboxesField}
              label={t('All types of target')}
              items={targets}
            />
            <Field
              name="relationship_types"
              component={AutocompleteField}
              multiple={true}
              options={relationships}
              renderOption={renderSelectOption}
              noOptionsText={t('No available options')}
              textfieldprops={{
                variant: 'standard',
                label: t('All types of relationship'),
                onFocus: searchTypes,
              }}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="reset_filters"
              label={t('Reset filters')}
              containerstyle={{ marginTop: 20 }}
            />
          </DialogContent>

          <DialogActions>
            <Button
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t('Expand')}
            </Button>
          </DialogActions>
        </Form>
      )}
    </Formik>
  );
}
