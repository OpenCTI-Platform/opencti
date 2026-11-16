import type { Issue } from './issue.ts';

const API = 'https://api.github.com';

interface RawIssue {
  number: number;
  title: string;
  body: string | null;
  labels: (string | { name?: string })[];
  pull_request?: unknown;
}

const request = async (path: string, token: string | undefined, init: RequestInit = {}): Promise<unknown> => {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'issue-triage-poc',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) throw new Error(`GitHub ${init.method ?? 'GET'} ${path} failed: ${response.status} ${await response.text()}`);
  return response.json();
};

const toIssue = (raw: RawIssue): Issue => ({
  number: raw.number,
  title: raw.title,
  body: raw.body ?? '',
  labels: raw.labels.map((label) => (typeof label === 'string' ? label : (label.name ?? ''))).filter(Boolean),
});

/** The most recently created closed issues: closed ones have had time to be labelled by a human. */
export const fetchClosedIssues = async (repo: string, limit: number, token?: string): Promise<Issue[]> => {
  const issues: Issue[] = [];
  for (let page = 1; issues.length < limit; page++) {
    const batch = (await request(`/repos/${repo}/issues?state=closed&sort=created&direction=desc&per_page=100&page=${page}`, token)) as RawIssue[];
    if (batch.length === 0) break;
    // The issues endpoint also returns pull requests.
    issues.push(...batch.filter((raw) => raw.pull_request === undefined).map(toIssue));
  }
  return issues.slice(0, limit);
};

export const fetchIssue = async (repo: string, number: number, token?: string): Promise<Issue> =>
  toIssue((await request(`/repos/${repo}/issues/${number}`, token)) as RawIssue);

export const postComment = async (repo: string, number: number, body: string, token: string): Promise<void> => {
  await request(`/repos/${repo}/issues/${number}/comments`, token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
  });
};
