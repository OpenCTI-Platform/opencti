// The requirement oidc of the OpenCTI platform, a hotlink (RFC-0012): removes the OpenID Connect
// provider link.ts added, by its identifier. Runs as link.ts does, given what it was given.

interface Input {
  contract: { url: { host: string } };
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Input;

const gql = async <T>(query: string, variables: Record<string, unknown> = {}): Promise<T> => {
  const answer = await fetch('http://localhost:8080/graphql', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env['APP__ADMIN__TOKEN']}` },
    body: JSON.stringify({ query, variables }),
  });
  const body = (await answer.json()) as { data: T; errors?: { message: string }[] };
  if (body.errors?.length) {
    console.error(`opencti: ${body.errors[0]!.message}`);
    process.exit(1);
  }
  return body.data;
};

const identifier = `oidc-${input.contract.url.host}`;
const listed = await gql<{ authenticationProviders: { edges: { node: { id: string; identifier_override: string | null } }[] } | null }>(
  'query { authenticationProviders(first: 500) { edges { node { id identifier_override } } } }',
);
for (const { node } of listed.authenticationProviders?.edges ?? []) {
  if (node.identifier_override === identifier) await gql('mutation ($id: ID!) { oidcProviderDelete(id: $id) }', { id: node.id });
}
