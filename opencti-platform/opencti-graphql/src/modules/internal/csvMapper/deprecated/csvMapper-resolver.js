import { csvMapperTest } from './csvMapper-domain';

const stixCyberObservableResolvers_deprecated = {
  Query: {
    csvMapperTest: (_, { configuration, content }, context) => csvMapperTest(context, context.user, configuration, content),
  },
};

export default stixCyberObservableResolvers_deprecated;
