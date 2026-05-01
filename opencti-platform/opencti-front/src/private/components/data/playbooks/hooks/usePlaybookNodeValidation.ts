/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { useEffect, useState } from 'react';
import { APP_BASE_PATH } from '../../../../../relay/environment';

export interface NodeValidationResult {
  node_id: string;
  is_valid: boolean;
}

/**
 * Fetches server-side entity-reference validation for all nodes in a playbook.
 * Returns a Map of nodeId → isValid that can be passed to computeNodes to
 * override the client-side structural checks with authoritative server data.
 *
 * The map is initially empty (optimistic: show no errors) and populates
 * asynchronously once the server responds.
 *
 * Uses a plain fetch (not Relay) to avoid Relay store caching issues on
 * queries whose results are not normalized by id.
 */
const usePlaybookNodeValidation = (playbookId: string): Map<string, boolean> => {
  const [validationMap, setValidationMap] = useState<Map<string, boolean>>(new Map());

  useEffect(() => {
    if (!playbookId) return;
    let cancelled = false;

    const query = `query PlaybookNodeValidation($id: ID!) {
      playbookNodeConfigurationValidation(id: $id) {
        node_id
        is_valid
      }
    }`;

    fetch(`${APP_BASE_PATH}/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ query, variables: { id: playbookId } }),
    })
      .then((r) => r.json())
      .then((json: { data?: { playbookNodeConfigurationValidation?: NodeValidationResult[] }; errors?: unknown[] }) => {
        if (cancelled) return;
        const results = json?.data?.playbookNodeConfigurationValidation ?? [];
        const map = new Map<string, boolean>();
        results.forEach(({ node_id, is_valid }) => map.set(node_id, is_valid));
        setValidationMap(map);
      })
      .catch(() => {
        // If the query fails (e.g. not EE, network error), fall back to client-side checks only
        if (!cancelled) setValidationMap(new Map());
      });

    return () => { cancelled = true; };
  }, [playbookId]);

  return validationMap;
};

export default usePlaybookNodeValidation;
