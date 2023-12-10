import griffon.util.AbstractMapResourceBundle;

import javax.annotation.Nonnull;
import java.util.Map;

import static java.util.Arrays.asList;
import static griffon.util.CollectionUtils.map;

public class Config extends AbstractMapResourceBundle {
    @Override
    protected void initialize(@Nonnull Map<String, Object> entries) {
        map(entries)
            .e("application", map()
                .e("title", "cs50")
                .e("startupGroups", asList("cs50"))
                .e("autoShutdown", true)
            )
            .e("mvcGroups", map()
                .e("cs50", map()
                    .e("model", "justinas.lt.Cs50Model")
                    .e("view", "justinas.lt.Cs50View")
                    .e("controller", "justinas.lt.Cs50Controller")
                )
            );
    }
}