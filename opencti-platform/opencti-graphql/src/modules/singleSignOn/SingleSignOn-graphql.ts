import { registerGraphqlSchema } from "../../graphql/schema";
import singleSignOnTypeDefs from "./SingleSignOn.graphql";
import singleSignOnResolver from './SingleSignOn-resolver';

registerGraphqlSchema({
  schema: singleSignOnTypeDefs,
  resolver: singleSignOnResolver
})