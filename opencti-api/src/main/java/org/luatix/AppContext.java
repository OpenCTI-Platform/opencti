package org.luatix;

import org.cfg4j.provider.ConfigurationProvider;
import org.luatix.base.Database;

public class AppContext {

    private static AppContext singleton;
    private Database base;
    private ConfigurationProvider cp;

    private AppContext() {
        //Nothing
    }

    public static AppContext context() {
        if(singleton == null) {
            singleton = new AppContext();
        }
        return singleton;
    }

    public Database database() {
        return base;
    }

    public AppContext database(Database base) {
        this.base = base;
        return this;
    }

    public ConfigurationProvider config() {
        return cp;
    }

    public AppContext config(ConfigurationProvider cp) {
        this.cp = cp;
        return this;
    }
}
