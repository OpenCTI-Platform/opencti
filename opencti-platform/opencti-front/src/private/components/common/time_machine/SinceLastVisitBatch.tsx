import React, { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { useIntl } from 'react-intl';
import { Badge, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { countLabel } from './timeMachineUtils';
import { SinceLastVisitBatchQuery, SinceLastVisitBatchQuery$data } from './__generated__/SinceLastVisitBatchQuery.graphql';

const sinceLastVisitBatchQuery = graphql`
  query SinceLastVisitBatchQuery($ids: [String!]!) {
    entitiesSinceLastVisit(ids: $ids) {
      entity_id
      first_visit
      last_seen_at
      new_relationships
      updates
      new_container_objects
    }
  }
`;

type SinceLastVisitRow = SinceLastVisitBatchQuery$data['entitiesSinceLastVisit'][number];

// Maximum number of elements checked per request (enforced by the API)
const BATCH_SIZE = 100;
const BATCH_DELAY_MS = 150;
// Requests of a row, failed batches included, before its badge is given up for the lifetime of the list
const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 3000;

interface SinceLastVisitBatchContextValue {
  register: (id: string) => void;
  results: Map<string, SinceLastVisitRow>;
}

const SinceLastVisitBatchContext = createContext<SinceLastVisitBatchContextValue | null>(null);

/**
 * Collects the ids of the knowledge rows displayed by a list and fetches, in batches,
 * what changed on each of them since the last visit of the user.
 */
export const SinceLastVisitBatchProvider = ({ enabled, children }: { enabled: boolean; children: ReactNode }) => {
  const [results, setResults] = useState<Map<string, SinceLastVisitRow>>(new Map());
  const pending = useRef<Set<string>>(new Set());
  const requested = useRef<Set<string>>(new Set());
  const failures = useRef<Map<string, number>>(new Map());
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const flush = useCallback(() => {
    timer.current = null;
    const ids = [...pending.current].slice(0, BATCH_SIZE);
    ids.forEach((id) => {
      pending.current.delete(id);
      requested.current.add(id);
    });
    if (ids.length === 0) return;
    fetchQuery<SinceLastVisitBatchQuery>(sinceLastVisitBatchQuery, { ids })
      .toPromise()
      .then((data) => {
        if (!mounted.current || !data) return;
        setResults((previous) => {
          const next = new Map(previous);
          data.entitiesSinceLastVisit.forEach((row) => next.set(row.entity_id, row));
          return next;
        });
      })
      .catch(() => {
        // The counters are an enhancement of the list: a failed batch is requested again later, a few times at most
        if (!mounted.current) return;
        const retried = ids.filter((id) => {
          const attempts = (failures.current.get(id) ?? 0) + 1;
          failures.current.set(id, attempts);
          return attempts < MAX_ATTEMPTS;
        });
        retried.forEach((id) => {
          requested.current.delete(id);
          pending.current.add(id);
        });
        if (retried.length > 0 && !timer.current) {
          timer.current = setTimeout(flush, RETRY_DELAY_MS);
        }
      });
    if (pending.current.size > 0) {
      timer.current = setTimeout(flush, 0);
    }
  }, []);

  const register = useCallback((id: string) => {
    if (!enabled || requested.current.has(id) || pending.current.has(id)) return;
    pending.current.add(id);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(flush, BATCH_DELAY_MS);
  }, [enabled, flush]);

  const value = useMemo(() => ({ register, results }), [register, results]);
  return <SinceLastVisitBatchContext.Provider value={value}>{children}</SinceLastVisitBatchContext.Provider>;
};

/**
 * Small indicator on a list row when the entity changed since the last visit of the user.
 * Only knowledge entities (domain objects and observables) are checked.
 */
export const SinceLastVisitRowBadge = ({ id, entityType }: { id: string; entityType?: string | null }) => {
  const context = useContext(SinceLastVisitBatchContext);
  const { t_i18n, rd } = useFormatter();
  const intl = useIntl();
  // Read without useAuth: lists can be rendered outside of an authenticated user context
  const { schema } = useContext(UserContext);
  const isKnowledge = useMemo(() => {
    if (!entityType || !schema) return false;
    return schema.sdos.some((type) => type.id === entityType) || schema.scos.some((type) => type.id === entityType);
  }, [entityType, schema]);
  useEffect(() => {
    if (context && isKnowledge && id) context.register(id);
  }, [context?.register, isKnowledge, id]);
  const result = context?.results.get(id);
  if (!result || result.first_visit) return null;
  const total = result.new_relationships + result.updates + result.new_container_objects;
  if (total === 0) return null;
  const parts = [
    result.new_relationships > 0 ? countLabel('new_relationships', result.new_relationships, t_i18n) : null,
    result.updates > 0 ? countLabel('updates', result.updates, t_i18n) : null,
    result.new_container_objects > 0 ? countLabel('new_container_objects', result.new_container_objects, t_i18n) : null,
  ].filter((part): part is string => !!part);
  const description = t_i18n('New since your last visit, by other users: {changes}', { values: { changes: intl.formatList(parts, { type: 'conjunction' }) } });
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          data-testid="since-last-visit-row-badge"
          style={{ position: 'absolute', left: 2, top: '50%', transform: 'translateY(-50%)', display: 'flex' }}
        >
          <Badge dot tone="brand" accessibleText={description} />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <span style={{ display: 'flex', flexDirection: 'column' }}>
          <span>{description}</span>
          {result.last_seen_at && <span>{t_i18n('Last visit {date}', { values: { date: rd(result.last_seen_at) } })}</span>}
        </span>
      </TooltipContent>
    </Tooltip>
  );
};
