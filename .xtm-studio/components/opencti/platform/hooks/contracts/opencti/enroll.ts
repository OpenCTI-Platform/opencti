// The contract opencti of the OpenCTI platform: the service account a consumer asks for, as a
// worker does, and its token. Runs in the platform's container, against its own API on
// localhost:8080, as the admin of the platform (APP__ADMIN__TOKEN of the container). It reads its
// input as JSON on its standard input (the input of every hook is described in the developer guide
// of XTM Studio) and answers JSON on its standard output.
//
// The data of its enrollment, all of it optional; without a service account, nothing is made.
//   service_account  { name }: the service account to make, in the group Administrators, which
//                    holds the capability BYPASS: a worker imports what the connectors send as
//                    the connector that sent it
// Answers { token }: a token of the service account, named xtm-studio, made again at each
// enrollment, the one made before revoked.

interface Input {
  enrollment: { service_account?: { name?: string } };
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Input;

const fail = (message: string): never => {
  console.error(`opencti: ${message}`);
  process.exit(1);
};

const gql = async <T>(query: string, variables: Record<string, unknown> = {}): Promise<T> => {
  let answer: Response;
  try {
    answer = await fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env['APP__ADMIN__TOKEN']}` },
      body: JSON.stringify({ query, variables }),
    });
  } catch (error) {
    return fail((error as Error).message);
  }
  const body = (await answer.json()) as { data: T; errors?: { message: string }[] };
  if (body.errors?.length) fail(body.errors[0]!.message);
  return body.data;
};

const name = input.enrollment.service_account?.name;
if (name) {
  interface User {
    id: string;
    name: string;
    api_tokens?: { id: string; name: string }[];
  }
  const users = await gql<{ users: { edges: { node: User }[] } }>('query ($search: String) { users(search: $search, first: 100) { edges { node { id name api_tokens { id name } } } } }', { search: name });
  let user = users.users.edges.map(({ node }) => node).find((each) => each.name === name);
  if (!user) {
    const groups = await gql<{ groups: { edges: { node: { id: string; name: string } }[] } }>('query { groups(search: "Administrators", first: 10) { edges { node { id name } } } }');
    const group = groups.groups.edges.map(({ node }) => node).find((each) => each.name === 'Administrators') ?? fail('no group Administrators');
    const added = await gql<{ userAdd: User }>('mutation ($input: UserAddInput!) { userAdd(input: $input) { id name api_tokens { id name } } }', {
      input: { name, user_service_account: true, groups: [group.id], prevent_default_groups: true },
    });
    user = added.userAdd;
  }
  for (const token of user.api_tokens ?? []) {
    if (token.name === 'xtm-studio') await gql('mutation ($userId: ID!, $id: ID!) { userAdminTokenRevoke(userId: $userId, id: $id) }', { userId: user.id, id: token.id });
  }
  const made = await gql<{ userAdminTokenAdd: { plaintext_token: string } }>(
    'mutation ($userId: ID!, $input: UserTokenAddInput!) { userAdminTokenAdd(userId: $userId, input: $input) { plaintext_token } }',
    { userId: user.id, input: { name: 'xtm-studio', duration: 'UNLIMITED' } },
  );
  console.log(JSON.stringify({ token: made.userAdminTokenAdd.plaintext_token }));
}
