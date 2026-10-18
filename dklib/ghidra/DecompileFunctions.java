// Writes Ghidra's C for each function to a file, for `dk ghidra`.
// Arguments: the output file, then function names (func_XXXXXXXX) or addresses.
//@category dk
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
            for (int i = 1; i < args.length; i++) {
                String hex = args[i].replaceFirst("^(func_|0x)", "");
                Address addr = toAddr(Long.parseLong(hex, 16));
                Function f = getFunctionAt(addr);
                if (f == null) {
                    f = createFunction(addr, null);
                }
                if (f == null) {
                    out.println("// " + args[i] + ": Ghidra found no function at " + addr + "\n");
                    continue;
                }
                DecompileResults r = decomp.decompileFunction(f, 120, monitor);
                out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC()
                        : "// " + args[i] + ": " + r.getErrorMessage() + "\n");
            }
        }
        decomp.dispose();
    }
}
