import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import React, { Suspense, useEffect, useState } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { InvestigationExpandFormTargetsDistributionFromQuery } from './__generated__/InvestigationExpandFormTargetsDistributionFromQuery.graphql';
import { InvestigationExpandFormTargetsDistributionToQuery } from './__generated__/InvestigationExpandFormTargetsDistributionToQuery.graphql';
import { InvestigationExpandFormRelDistributionQuery } from './__generated__/InvestigationExpandFormRelDistributionQuery.graphql';
import CheckboxesField from '../../../../components/CheckboxesField';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useAuth from '../../../../utils/hooks/useAuth';
import { GraphLink, GraphNode } from '../../../../components/graph/graph.types';
import { FieldOption } from '../../../../utils/field';

// The number of elements targeted by the given
// entities ids, sorted by type of entity.
const investigationExpandFormTargetsDistributionFromQuery = graphql`
  query InvestigationExpandFormTargetsDistributionFromQuery($ids: [String]) {
    stixRelationshipsDistribution(
      fromId: $ids
      isTo: true
      operation: count
      field: "entity_type"
      relationship_type: "stix-relationship"
      aggregateOnConnections: true
    ) {
      label
      value
    }
  }
`;

// The number of elements targeting the given
// entities ids, sorted by type of entity.
const investigationExpandFormTargetsDistributionToQuery = graphql`
  query InvestigationExpandFormTargetsDistributionToQuery($ids: [String]) {
    stixRelationshipsDistribution(
      toId: $ids
      isTo: false
      operation: count
      field: "entity_type"
      relationship_type: "stix-relationship"
      aggregateOnConnections: true
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
      fromOrToId: $ids
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  checkboxesContainer: {
    display: 'flex',
    justifyContent: 'space-between',
  },
  fallback: {
    minHeight: 200,
    minWidth: 200,
    display: 'flex',
    alignItems: 'center',
  },
}));

type FormData = {
  entity_types: FieldOption[];
  relationship_types: FieldOption[];
  reset_filters: boolean;
};

export type InvestigationExpandFormProps = {
  links: GraphLink[];
  selectedNodes: GraphNode[];
  onSubmit: (data: FormData, helpers: FormikHelpers<FormData>) => void;
  onReset: () => void;
};

// Refs of queries instantiated by the wrapper (bottom of the file).
type InvestigationExpandFormContentProps = InvestigationExpandFormProps & {
  distributionRelQueryRef: PreloadedQuery<InvestigationExpandFormRelDistributionQuery>;
  distributionFromQueryRef: PreloadedQuery<InvestigationExpandFormTargetsDistributionFromQuery>;
  distributionToQueryRef: PreloadedQuery<InvestigationExpandFormTargetsDistributionToQuery>;
};

const InvestigationExpandFormContent = ({
  links,
  selectedNodes,
  onSubmit,
  onReset,
  distributionRelQueryRef,
  distributionFromQueryRef,
  distributionToQueryRef,
}: InvestigationExpandFormContentProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { schema } = useAuth();

  const distributionRel = usePreloadedQuery(
    investigationExpandFormRelDistributionQuery,
    distributionRelQueryRef,
  );
  const distributionFrom = usePreloadedQuery(
    investigationExpandFormTargetsDistributionFromQuery,
    distributionFromQueryRef,
  );
  const distributionTo = usePreloadedQuery(
    investigationExpandFormTargetsDistributionToQuery,
    distributionToQueryRef,
  );

  // List of items that are given to the Checkboxes component in the form.
  const [targets, setTargets] = useState<FieldOption[]>([]);
  const [relationships, setRelationships] = useState<FieldOption[]>([]);

  // Nodes and edges we have in our graph.
  // // Used to compute the difference between total count returned by
  // the query and what is already displayed.
  const [existingTargets, setExistingTargets] = useState<
    Map<string, Map<string, number>>
  >(new Map());
  const [existingRels, setExistingRels] = useState<
    Map<string, Map<string, string[]>>
  >(new Map());

  // How many entity types and rel types we already have in the graph.
  useEffect(() => {
    const countTargets = new Map<string, Map<string, number>>();
    const countRels = new Map<string, Map<string, string[]>>();

    links.forEach((link) => {
      if (typeof link.source === 'string' || typeof link.target === 'string') {
        return;
      }
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

  useEffect(() => {
    // A map where each key of the Map is a relationship type and
    // the associated value is a Set of ids of the elements in
    // relation with all selected nodes.
    //
    // Used to compute the difference between total count returned by
    // the query and what is already displayed in the graph.
    const existingRelsSelected = new Map<string, Set<string>>();
    selectedNodes.forEach((node) => {
      const nodeRels = existingRels.get(node.id);
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

    // relations refs involving the user are not expandable
    const relationRefsWithUser = new Set(
      Array.from(schema.schemaRelationsRefTypesMapping.values())
        .flat()
        .filter((ref) => ref.toTypes.includes('User'))
        .map((ref) => ref.name.toLowerCase()),
    );

    const nonNullDistribution = (
      distributionRel.stixRelationshipsDistribution ?? []
    )
      // Use of flatMap() to do both filter() and map() in one step.
      .flatMap((rel) => (rel
        ? [
            {
              label: rel.label.toLowerCase(),
              // Decrease from the count of already displayed elements.
              // toLowerCase() because relationship names are pascalized
              // in elAggregationRelationsCount().
              value:
                  (rel.value ?? 0)
                  - (
                    existingRelsSelected.get(rel.label.toLowerCase())
                    ?? new Set()
                  ).size,
            },
          ]
        : []))
      // Remove from the list relations with nothing to add and relations ref involving the user
      .filter(({ label, value }) => value > 0 && !relationRefsWithUser?.has(label.replace('-', '')))
      .sort((a, b) => (b.value ?? 0) - (a.value ?? 0));
    setRelationships(
      nonNullDistribution.map(({ label, value }) => ({
        label: `${t_i18n(`relationship_${label}`)} (${value})`,
        value: label,
      })),
    );
  }, [distributionRel, selectedNodes, existingRels, setRelationships]);

  useEffect(() => {
    // A map where each key of the Map is a target type and
    // the associated value is the number of the elements in
    // relation with all selected nodes.
    //
    // Used to compute the difference between total count returned by
    // the query and what is already displayed in the graph.
    const existingTargetsSelected = new Map<string, number>();
    selectedNodes.forEach((node) => {
      const nodeTargets = existingTargets.get(node.id);
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

    // Merge both 'from' relationships and 'to' relationships.
    const distribution: { label: string; value: number }[] = [];
    [distributionFrom, distributionTo].forEach(
      ({ stixRelationshipsDistribution }) => {
        stixRelationshipsDistribution?.forEach((newTarget) => {
          if (newTarget) {
            const target = distribution.find(
              (item) => item.label === newTarget.label,
            );
            if (target) {
              target.value += newTarget.value ?? 0;
            } else {
              distribution.push({
                label: newTarget.label,
                value: newTarget.value ?? 0,
              });
            }
          }
        });
      },
    );

    const graphDistribution = distribution
      .map((target) => ({
        label: target.label,
        // Decrease from the count of already displayed elements.
        // toLowerCase() because relationship names are pascalized
        // in elAggregationRelationsCount().
        value:
          target.value
          - (existingTargetsSelected.get(target.label.toLowerCase()) ?? 0),
      }))
      // Remove from the list entities with nothing to add and entities that are not knowledge
      .filter(({ label, value }) => label !== 'User' && value > 0)
      .sort((a, b) => a.label.localeCompare(b.label));

    // Uses to determine which key of translation to use below.
    const relationshipsNames = schema.scrs.map(({ label }) => label);
    setTargets(
      graphDistribution.map(({ label, value }) => {
        const isRelationship = relationshipsNames.includes(label.toLowerCase());
        let translation = t_i18n(`entity_${label}`);
        if (isRelationship) {
          translation = `${t_i18n(`relationship_${label.toLowerCase()}`)} (${t_i18n('Relationship')})`;
        }
        return {
          label: `${translation} (${value})`,
          value: label,
        };
      }),
    );
  }, [
    distributionFrom,
    distributionTo,
    selectedNodes,
    existingTargets,
    setTargets,
  ]);

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
          <DialogTitle>{t_i18n('Expand elements')}</DialogTitle>
          <DialogContent>
            <div className={classes.checkboxesContainer}>
              <Field
                name="entity_types"
                component={CheckboxesField}
                label={t_i18n('All types of target')}
                items={targets}
              />
              <Field
                name="relationship_types"
                component={CheckboxesField}
                label={t_i18n('All types of relationship')}
                items={relationships}
              />
            </div>
            <Field
              component={SwitchField}
              type="checkbox"
              name="reset_filters"
              label={t_i18n('Reset filters')}
              containerstyle={{ marginTop: 20 }}
            />
          </DialogContent>

          <DialogActions>
            <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Expand')}
            </Button>
          </DialogActions>
        </Form>
      )}
    </Formik>
  );
};

// Wrapper component that prepares queries.
const InvestigationExpandForm = (props: InvestigationExpandFormProps) => {
  const classes = useStyles();

  // Number of relations grouped by type of relation.
  const [distributionRelQueryRef, loadDistributionRelQuery] = useQueryLoader<InvestigationExpandFormRelDistributionQuery>(
    investigationExpandFormRelDistributionQuery,
  );

  // Number of targets source of a relation grouped by entity type.
  const [distributionFromQueryRef, loadDistributionFromQuery] = useQueryLoader<InvestigationExpandFormTargetsDistributionFromQuery>(
    investigationExpandFormTargetsDistributionFromQuery,
  );

  // Number of targets destination of a relation grouped by entity type.
  const [distributionToQueryRef, loadDistributionToQuery] = useQueryLoader<InvestigationExpandFormTargetsDistributionToQuery>(
    investigationExpandFormTargetsDistributionToQuery,
  );

  useEffect(() => {
    const ids = Array.from(props.selectedNodes).map((node) => node.id);
    loadDistributionRelQuery({ ids });
    loadDistributionFromQuery({ ids });
    loadDistributionToQuery({ ids });
  }, [props.selectedNodes]);

  const Fallback = (
    <div className={classes.fallback}>
      <Loader variant={LoaderVariant.inElement} />
    </div>
  );

  return distributionRelQueryRef
    && distributionFromQueryRef
    && distributionToQueryRef ? (
        <Suspense fallback={Fallback}>
          <InvestigationExpandFormContent
            {...props}
            distributionRelQueryRef={distributionRelQueryRef}
            distributionFromQueryRef={distributionFromQueryRef}
            distributionToQueryRef={distributionToQueryRef}
          />
        </Suspense>
      ) : (
        Fallback
      );
};

export default InvestigationExpandForm;
