import { useCallback, useEffect, useRef, useState } from 'react';
import { callAgentStream } from './agentApi';

interface UseAgentStreamOptions {
  /** Transform each streamed chunk before setting content (e.g. cleanHtmlTags) */
  transformContent?: (raw: string) => string;
}

interface UseAgentStreamReturn {
  content: string;
  setContent: (content: string) => void;
  loading: boolean;
  error: string | undefined;
  generatedAt: string | null;
  execute: (agentSlug: string, prompt: string) => void;
  abort: () => void;
}

/**
 * Reusable hook for streaming agent calls via SSE.
 *
 * Encapsulates: AbortController lifecycle, requestAnimationFrame-batched
 * content updates, loading/error/generatedAt state, and cleanup on unmount.
 *
 * Tokens are accumulated in a mutable ref and flushed to React state once
 * per animation frame (~16ms), preventing excessive re-renders from rapid
 * SSE chunks — the same pattern used by filigran-copilot's WebSocket chat.
 */
const useAgentStream = (options?: UseAgentStreamOptions): UseAgentStreamReturn => {
  const transform = options?.transformContent ?? ((s: string) => s);
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>(undefined);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const contentBufferRef = useRef('');
  const rafRef = useRef<number | null>(null);

  useEffect(() => () => {
    abortRef.current?.abort();
    if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
  }, []);

  const abort = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const execute = useCallback((agentSlug: string, prompt: string) => {
    abortRef.current?.abort();
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    const controller = new AbortController();
    abortRef.current = controller;

    contentBufferRef.current = '';
    setLoading(true);
    setContent('');
    setError(undefined);
    setGeneratedAt(null);

    callAgentStream(
      agentSlug,
      prompt,
      (partial) => {
        contentBufferRef.current = transform(partial);
        if (rafRef.current === null) {
          rafRef.current = requestAnimationFrame(() => {
            setContent(contentBufferRef.current);
            rafRef.current = null;
          });
        }
      },
      controller.signal,
    )
      .then((result) => {
        if (rafRef.current !== null) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = null;
        }
        if (result.status === 'error') {
          setError(result.error ?? 'An unknown error occurred');
        } else {
          setContent(transform(result.content));
          setGeneratedAt(new Date().toISOString());
        }
        setLoading(false);
      })
      .catch((err: Error) => {
        if (err.name !== 'AbortError') {
          setError(err.toString());
          setLoading(false);
        }
      });
  }, [transform]);

  return { content, setContent, loading, error, generatedAt, execute, abort };
};

export default useAgentStream;
