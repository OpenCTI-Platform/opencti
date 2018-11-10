package org.opencti.model.database;

public class BaseQuery {

    private String query;
    private Object[] parameters;

    public BaseQuery(String query) {
        this.query = query;
        this.parameters = new Object[0];
    }

    public static BaseQuery from(String query) {
        return new BaseQuery(query);
    }

    public BaseQuery withParams(Object... parameters) {
        this.parameters = parameters;
        return this;
    }

    public BaseQuery(String query, Object... parameters) {
        this.query = query;
        this.parameters = parameters;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public Object[] getParameters() {
        return parameters;
    }

    public void setParameters(Object[] parameters) {
        this.parameters = parameters;
    }
}
