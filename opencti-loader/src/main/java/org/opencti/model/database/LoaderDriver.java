package org.opencti.model.database;

import org.cfg4j.provider.ConfigurationProvider;

import java.util.List;

public abstract class LoaderDriver {

    LoaderDriver(ConfigurationProvider cp) {
        init(cp);
    }
    abstract void init(ConfigurationProvider cp);
    public abstract void execute(BaseQuery query);
    public abstract void close();
}
