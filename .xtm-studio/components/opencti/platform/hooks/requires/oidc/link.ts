// The requirement oidc of the OpenCTI platform, a hotlink (RFC-0012): adds the OpenID Connect
// provider of a link to the platform, through its API on localhost:8080, as its admin
// (APP__ADMIN__TOKEN of the container), while it runs. It reads, as JSON on its standard input,
// what the enrollment gives a template: the contract of the provider, the client the enrollment
// asked for, and what the provider answered. A provider of the same identifier, as a restored
// platform holds, is replaced.

interface Input {
  provider: { name: string };
  contract: { url: { host: string; machine: { value: string } } };
  enrollment: { client: { id: string } };
  output: { client_id: string; client_secret: string };
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Input;

const gql = async <T>(query: string, variables: Record<string, unknown> = {}): Promise<T> => {
  let answer: Response;
  try {
    answer = await fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env['APP__ADMIN__TOKEN']}` },
      body: JSON.stringify({ query, variables }),
    });
  } catch (error) {
    console.error(`opencti: ${(error as Error).message}`);
    process.exit(1);
  }
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
await gql('mutation ($input: OidcInput!) { oidcProviderAdd(input: $input) { id } }', {
  input: {
    base: { name: `${input.provider.name} (OIDC)`, enabled: true, identifier_override: identifier },
    configuration: {
      issuer: input.contract.url.machine.value,
      client_id: input.output.client_id,
      client_secret: { new_value_cleartext: input.output.client_secret },
      scopes: ['openid', 'email', 'profile'],
      logout_remote: false,
      use_proxy: false,
      user_info_mapping: { email_expr: 'email', name_expr: 'name' },
      groups_mapping: { default_groups: [], groups_expr: [], groups_mapping: [], auto_create_groups: false, prevent_default_groups: false, extend_platform_groups: false },
      organizations_mapping: { default_organizations: [], organizations_expr: [], organizations_mapping: [], auto_create_organizations: false },
      extra_conf: [],
    },
  },
});
