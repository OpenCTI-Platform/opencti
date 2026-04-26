import { useState } from 'react';
import { graphql } from 'react-relay';
import { isFilterGroupFormatCorrect } from '../../../../utils/filters/filtersUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { callAgent } from '../../../../utils/ai/agentApi';
import { useChatbot } from '../../chatbox/ChatbotContext';
import { RelayError } from '../../../../relay/relayTypes';
import { extractJsonContent } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import type { AINLQMutation, AINLQMutation$data } from './__generated__/AINLQMutation.graphql';

// ── GraphQL mutation (legacy NLQ via built-in AI) ───────────────────────

const aiNLQMutation = graphql`
  mutation AINLQMutation($search: String!) {
    aiNLQ(search: $search) {
      filters
      notResolvedValues
    }
  }
`;

// ── Constants & types ───────────────────────────────────────────────────

export const NLQ_INTENT = 'cti.nlq_search';

interface ParsedNlqResponse {
  filters?: string;
  notResolvedValues: string[];
  error?: string;
}

// ── Pure helpers ────────────────────────────────────────────────────────

const parseNlqAgentResponse = (content: string): ParsedNlqResponse | null => {
  try {
    const jsonContent = extractJsonContent(content);
    const parsed = JSON.parse(jsonContent);

    // Accept either the legacy shape { filters, notResolvedValues }
    // or directly a filter group object.
    if (parsed && typeof parsed === 'object') {
      const parsedError = typeof parsed.error === 'string' && parsed.error.length > 0
        ? parsed.error
        : undefined;
      const notResolvedValues = Array.isArray(parsed.notResolvedValues)
        ? parsed.notResolvedValues.filter((value: unknown): value is string => typeof value === 'string')
        : [];

      if ('filters' in parsed) {
        if (!parsedError && typeof parsed.filters !== 'string' && !isFilterGroupFormatCorrect(parsed.filters)) {
          return null;
        }
        const filters = typeof parsed.filters === 'string'
          ? parsed.filters
          : isFilterGroupFormatCorrect(parsed.filters)
            ? JSON.stringify(parsed.filters)
            : undefined;
        return { filters, notResolvedValues, error: parsedError };
      }

      if (parsedError) {
        return { notResolvedValues, error: parsedError };
      }

      if (!isFilterGroupFormatCorrect(parsed)) {
        return null;
      }

      return {
        filters: JSON.stringify(parsed),
        notResolvedValues,
        error: parsedError,
      };
    }
    return null;
  } catch {
    return null;
  }
};

const toValidSerializedFilterGroup = (filters?: string): string | null => {
  if (!filters) {
    return null;
  }
  try {
    const parsed = JSON.parse(filters);
    return isFilterGroupFormatCorrect(parsed) ? JSON.stringify(parsed) : null;
  } catch {
    return null;
  }
};

const buildNlqPrompt = (searchKeyword: string): string => searchKeyword;

// ── Hook ────────────────────────────────────────────────────────────────

export interface NLQCallbacks {
  onFiltersResolved: (keyword: string, filters?: string, notResolvedValues?: readonly string[]) => void;
  onError: (message: string) => void;
}

export const useAINLQ = (callbacks: NLQCallbacks) => {
  const [isLoading, setIsLoading] = useState(false);
  const { t_i18n } = useFormatter();
  const { xtmOneConfigured } = useChatbot();
  const [commitMutation] = useApiMutation<AINLQMutation>(aiNLQMutation);

  const runLegacyNlq = (searchKeyword: string) => {
    commitMutation({
      variables: { search: searchKeyword },
      onCompleted: (response: AINLQMutation$data) => {
        setIsLoading(false);
        callbacks.onFiltersResolved(
          searchKeyword,
          response.aiNLQ?.filters,
          response.aiNLQ?.notResolvedValues ?? [],
        );
      },
      onError: (error: Error) => {
        setIsLoading(false);
        const { errors } = (error as unknown as RelayError).res;
        callbacks.onError(errors.at(0)?.message ?? t_i18n('NLQ mutation failed'));
      },
    });
  };

  const runXtmOneNlq = async (searchKeyword: string, agentSlug?: string): Promise<void> => {
    if (!agentSlug) {
      setIsLoading(false);
      callbacks.onError(t_i18n('No NLQ agent is available'));
      return;
    }

    const response = await callAgent(agentSlug, buildNlqPrompt(searchKeyword));
    if (response.status === 'error') {
      setIsLoading(false);
      if (response.code === 503) {
        callbacks.onError(t_i18n('XTM One is unreachable'));
      } else {
        callbacks.onError(response.error ?? t_i18n('NLQ agent call failed'));
      }
      return;
    }

    const parsedResponse = parseNlqAgentResponse(response.content);
    if (!parsedResponse) {
      setIsLoading(false);
      callbacks.onError(t_i18n('NLQ agent returned an unreadable response'));
      return;
    }

    if (parsedResponse.error) {
      setIsLoading(false);
      callbacks.onError(parsedResponse.error);
      return;
    }

    const safeSerializedFilters = toValidSerializedFilterGroup(parsedResponse.filters);
    if (!safeSerializedFilters) {
      setIsLoading(false);
      callbacks.onError(t_i18n('NLQ agent returned invalid filters'));
      return;
    }

    setIsLoading(false);
    callbacks.onFiltersResolved(searchKeyword, safeSerializedFilters, parsedResponse.notResolvedValues);
  };

  const search = (searchKeyword: string, agentSlug?: string) => {
    setIsLoading(true);
    if (xtmOneConfigured === true) {
      runXtmOneNlq(searchKeyword, agentSlug).catch((err) => {
        setIsLoading(false);
        callbacks.onError((err as Error)?.message ?? t_i18n('NLQ call failed'));
      });
    } else {
      runLegacyNlq(searchKeyword);
    }
  };

  return { search, isLoading };
};
