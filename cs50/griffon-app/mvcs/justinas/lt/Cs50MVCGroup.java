package justinas.lt;

import javax.inject.Named;
import griffon.core.mvc.MVCGroup;
import org.codehaus.griffon.runtime.core.mvc.AbstractTypedMVCGroup;
import javax.annotation.Nonnull;

@Named("cs50")
public class Cs50MVCGroup extends AbstractTypedMVCGroup<Cs50Model, Cs50View, Cs50Controller> {
    public Cs50MVCGroup(@Nonnull MVCGroup delegate) {
        super(delegate);
    }
}