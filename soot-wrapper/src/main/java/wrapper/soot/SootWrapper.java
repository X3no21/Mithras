package wrapper.soot;

import java.io.*;
import java.util.Collections;
import java.lang.Exception;

import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.options.Options;
import soot.util.Chain;

public class SootWrapper {

    private Chain<SootClass> classes = null;

    public SootWrapper(String inputFile, String androidJars, String outputFormat) {
        try {
            Options.v().set_process_dir(Collections.singletonList(inputFile));
            Options.v().set_prepend_classpath(true);
            Options.v().set_whole_program(true);
            Options.v().set_force_overwrite(true);

            if (outputFormat.equals("jimple")) {
                Options.v().set_output_format(Options.output_format_jimple);
            } else if (outputFormat.equals("shimple")) {
                Options.v().set_output_format(Options.output_format_shimple);
            }

            Options.v().set_android_jars(androidJars);
            Options.v().set_src_prec(Options.src_prec_apk);
            Options.v().set_process_multiple_dex(true);

            Options.v().set_include_all(true);
            Options.v().set_keep_line_number(true);

            Options.v().set_allow_phantom_refs(true);
            Options.v().setPhaseOption("cg", "all-reachable:true");
            Options.v().setPhaseOption("jb.dae", "enabled:false");
            Options.v().setPhaseOption("jb.uce", "enabled:false");
            Options.v().setPhaseOption("jj.dae", "enabled:false");
            Options.v().setPhaseOption("jj.uce", "enabled:false");
            Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);

            Scene.v().loadNecessaryClasses();
            PackManager.v().runPacks();

            classes = Scene.v().getClasses();
        } catch (Exception e) {
           e.printStackTrace();
           return;
        }
    }

    public Chain<SootClass> getClasses() {
        return classes;
    }
}
