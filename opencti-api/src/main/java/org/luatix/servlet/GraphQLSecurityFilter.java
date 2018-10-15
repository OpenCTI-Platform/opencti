package org.luatix.servlet;

import javax.servlet.*;
import java.io.IOException;

public class GraphQLSecurityFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("GraphQLSecurityFilter init");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("GraphQLSecurityFilter doFilter");
        chain.doFilter(request, response);
    }
}
