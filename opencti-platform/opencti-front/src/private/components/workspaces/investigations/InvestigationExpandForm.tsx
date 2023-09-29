import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import React, { useEffect, useState } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import SwitchField from '../../../../components/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import {
  InvestigationExpandFormTargetsDistributionQuery$data,
} from './__generated__/InvestigationExpandFormTargetsDistributionQuery.graphql';
import {
  InvestigationExpandFormRelDistributionQuery$data,
} from './__generated__/InvestigationExpandFormRelDistributionQuery.graphql';
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

// The number of relationships linked by the given entities.
const investigationExpandFormRelDistributionQuery = graphql`
  query InvestigationExpandFormRelDistributionQuery($ids: [String]) {
    stixRelationshipsDistribution(
      elementId: $ids
      operation: count
      field: "entity_type"
      relationship_type: "stix-relationship"
      aggregateOnConnections: false
    ) {
      label
      value
    }
  }
`;

const useStyles = makeStyles(() => ({
  checkboxesContainer: {
    display: 'flex',
    gap: 24,
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
    id: string;
    entity_type: string;
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

  const [existingTargets, setExistingTargets] = useState<Map<string, Map<string, number>>>(new Map());
  const [existingRels, setExistingRels] = useState<Map<string, Map<string, string[]>>>(new Map());

  // How many entity types and rel types we already have in the graph.
  useEffect(() => {
    const countTargets = new Map<string, Map<string, number>>();
    const countRels = new Map<string, Map<string, string[]>>();

    links.forEach((link) => {
      // toLowerCase() because relationship names are pascalized
      const relType = link.entity_type.toLowerCase();

      const from = link.source.id;
      const to = link.target.id;
      // Init Maps if required
      if (from && !countTargets.has(from)) {
        countTargets.set(from, new Map());
      }
      if (to && !countTargets.has(to)) {
        countTargets.set(to, new Map());
      }
      if (from && !countRels.has(from)) {
        countRels.set(from, new Map());
      }
      if (to && !countRels.has(to)) {
        countRels.set(to, new Map());
      }

      // toLowerCase() because relationship names are pascalized
      // in elAggregationRelationsCount().
      const typeFrom = (link.target.entity_type ?? '').toLowerCase();
      const targetFrom = countTargets.get(from);
      if (targetFrom) {
        const currentTarget = targetFrom?.get(typeFrom);
        if (currentTarget !== undefined) {
          targetFrom.set(typeFrom, currentTarget + 1);
        } else {
          targetFrom.set(typeFrom, 1);
        }
      }
      const relFrom = countRels.get(from);
      if (relFrom) {
        const currentRel = relFrom?.get(relType);
        if (currentRel !== undefined) {
          relFrom.set(relType, [...currentRel, link.id]);
        } else {
          relFrom.set(relType, [link.id]);
        }
      }

      // toLowerCase() because relationship names are pascalized
      // in elAggregationRelationsCount().
      const typeTo = (link.source.entity_type ?? '').toLowerCase();
      const targetTo = countTargets.get(to);
      if (targetTo) {
        const current = targetTo?.get(typeTo);
        if (current !== undefined) {
          targetTo.set(typeTo, current + 1);
        } else {
          targetTo.set(typeTo, 1);
        }
      }
      const relTo = countRels.get(to);
      if (relTo) {
        const currentRel = relTo?.get(relType);
        if (currentRel !== undefined) {
          relTo.set(relType, [...currentRel, link.id]);
        } else {
          relTo.set(relType, [link.id]);
        }
      }
    });

    setExistingTargets(countTargets);
    setExistingRels(countRels);
  }, [links, setExistingRels, setExistingTargets]);

  // Fetch all possible relationships linked to the nodes to expand.
  useEffect(() => {
    async function fetchRelationships() {
      if (selectedNodes.length === 0) return;
      const nodeIds = Array.from(selectedNodes).map((node) => node.id);

      const { stixRelationshipsDistribution } = await fetchQuery(
        investigationExpandFormRelDistributionQuery,
        { ids: nodeIds },
      ).toPromise() as InvestigationExpandFormRelDistributionQuery$data;

      const existingRelsSelected = new Map<string, Set<string>>();
      nodeIds.forEach((node) => {
        const nodeRels = existingRels.get(node);
        if (nodeRels) {
          nodeRels.forEach((value, key) => {
            const current = existingRelsSelected.get(key);
            if (current !== undefined) {
              value.forEach((val) => current.add(val));
            } else {
              existingRelsSelected.set(key, new Set(value));
            }
          });
        }
      });

      const nonNullDistribution = (stixRelationshipsDistribution ?? [])
        // Use of flatMap() to do both filter() and map() in one step.
        .flatMap((rel) => (rel ? [{
          label: rel.label,
          // Decrease from the count of already displayed elements.
          // toLowerCase() because relationship names are pascalized
          // in elAggregationRelationsCount().
          value: (rel.value ?? 0) - (existingRelsSelected.get(rel.label.toLowerCase()) ?? new Set()).size,
        }] : []))
        // Remove from the list entities with nothing to add.
        .filter(({ value }) => value > 0)
        .sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

      setRelationships(
        nonNullDistribution
          .map(({ label, value }) => ({
            label: `${label} (${value})`,
            value: label,
          })),
      );
    }
    fetchRelationships();
  }, [selectedNodes, existingRels, setRelationships]);

  // Fetch all possible targets connected to the nodes to expand.
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
          // toLowerCase() because relationship names are pascalized
          // in elAggregationRelationsCount().
          value: (target.value ?? 0) - (existingTargetsSelected.get(target.label.toLowerCase()) ?? 0),
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
            <div className={classes.checkboxesContainer}>
              <Field
                name="entity_types"
                component={CheckboxesField}
                label={t('All types of target')}
                items={targets}
              />
              <Field
                name="relationship_types"
                component={CheckboxesField}
                label={t('All types of relationship')}
                items={relationships}
              />
            </div>
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
