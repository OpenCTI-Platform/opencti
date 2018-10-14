package org.luatix.Basic;

import com.coxautodev.graphql.tools.GraphQLQueryResolver;

public class About implements GraphQLQueryResolver {

    public String about() {
        return "Welcome to openCTI graphQL API.";
    }
}
