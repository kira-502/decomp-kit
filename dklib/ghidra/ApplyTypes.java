// Teaches the Ghidra project what the C already knows, for `dk ghidra`.
// Arguments: types.h and labels.txt from dklib/ghidra_types.py.
// Parses each declaration of types.h on its own, gives every func_ its prototype,
// every D_ global its type, names functions func_XXXXXXXX and data D_XXXXXXXX.
//@category dk
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ApplyTypes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String text = Files.readString(Path.of(args[0]));
        Memory mem = currentProgram.getMemory();
        SymbolTable st = currentProgram.getSymbolTable();

        // The ELF has no section for the zeroed data after it: give Ghidra that block.
        if (args.length > 3) {
            Address bss = toAddr(Long.parseLong(args[2], 16));
            long len = Long.parseLong(args[3], 16);
            if (len > 0 && !mem.contains(bss)) {
                MemoryBlock b = mem.createUninitializedBlock("bss", bss, len, false);
                b.setRead(true);
                b.setWrite(true);
            }
        }

        // Labels first: they also bound arrays of unknown length.
        TreeMap<Long, String> labels = new TreeMap<>();
        List<String[]> switches = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] w = line.trim().split(" ");
            if (w.length > 2 && w[0].equals("JT")) {
                switches.add(w);
            } else if (w.length == 2) {
                labels.put(Long.parseLong(w[1], 16), w[0]);
            }
        }

        // Switches: give each jump its table's cases, as Ghidra's SwitchOverride script does,
        // so the decompiler shows a switch instead of "Could not recover jumptable".
        int jts = 0;
        for (String[] w : switches) {
            Address jr = toAddr(Long.parseLong(w[1], 16));
            ArrayList<Address> dests = new ArrayList<>();
            for (int i = 2; i < w.length; i++) {
                Address d = toAddr(Long.parseLong(w[i], 16));
                if (!dests.contains(d)) {
                    dests.add(d);
                }
            }
            try {
                for (Address d : dests) {
                    if (getInstructionAt(d) == null) {
                        disassemble(d);
                    }
                }
                Instruction ins = getInstructionAt(jr);
                Function f = getFunctionContaining(jr);
                if (ins == null || f == null) {
                    continue;
                }
                if (ins.getFlowOverride() != FlowOverride.NONE) {
                    ins.setFlowOverride(FlowOverride.NONE);
                }
                for (Reference r : ins.getReferencesFrom()) {
                    if (r.getReferenceType() == RefType.COMPUTED_JUMP) {
                        currentProgram.getReferenceManager().delete(r);
                    }
                }
                for (Address d : dests) {
                    ins.addOperandReference(0, d, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
                }
                new JumpTable(jr, dests, true, 0).writeOverride(f);
                CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
                jts++;
            } catch (Exception ex) {
                // a table we can't place leaves Ghidra's own view of that function
            }
        }
        int named = 0;
        for (Map.Entry<Long, String> e : labels.entrySet()) {
            Address a = toAddr(e.getKey());
            if (!e.getValue().startsWith("D_") || !mem.contains(a)) {
                continue;
            }
            Symbol s = st.getGlobalSymbol(e.getValue(), a);
            if (s == null) {
                s = st.createLabel(a, e.getValue(), SourceType.USER_DEFINED);
            }
            s.setPrimary();
            named++;
        }

        CParser parser = new CParser(currentProgram.getDataTypeManager(), true, null);
        int bad = 0;
        List<String> errs = new ArrayList<>();
        for (String piece : text.split("/\\*@\\*/")) {
            if (piece.isBlank()) {
                continue;
            }
            try {
                parser.parse(piece);
            } catch (Throwable t) {
                bad++;
                if (errs.size() < 5) {
                    errs.add(piece.strip().split("\n")[0] + "  <- " + t.getMessage().split("\n")[0]);
                }
            }
        }
        // A type whose definition changed since the last teach came back as "X.conflict":
        // it replaces the old X everywhere and takes its name.
        DataTypeManager dtm0 = currentProgram.getDataTypeManager();
        List<DataType> conflicted = new ArrayList<>();
        for (java.util.Iterator<DataType> it = dtm0.getAllDataTypes(); it.hasNext();) {
            DataType t = it.next();
            if (t.getName().matches(".+\\.conflict[0-9]*")) {
                conflicted.add(t);
            }
        }
        for (DataType c : conflicted) {
            String base = c.getName().replaceFirst("\\.conflict[0-9]*$", "");
            try {
                DataType old = dtm0.getDataType(c.getCategoryPath(), base);
                if (old != null && old != c) {
                    dtm0.replaceDataType(old, c, true);
                }
                c.setName(base);
            } catch (Exception ex) {
                // leave the copy; the count below shows it
            }
        }

        // Each view of a global came as `typedef T dk_G<k>_D_X...;` (k = 0 best).
        TreeMap<String, TreeMap<Integer, DataType>> views = new TreeMap<>();
        List<DataType> carriers = new ArrayList<>();
        Pattern carrier = Pattern.compile("dk_G([0-9]+)_(D_[0-9A-F]+)");
        for (Map.Entry<String, DataType> e : parser.getTypes().entrySet()) {
            Matcher m = carrier.matcher(e.getKey());
            if (m.matches() && e.getValue() instanceof TypeDef td) {
                views.computeIfAbsent(m.group(2), k -> new TreeMap<>()).put(Integer.parseInt(m.group(1)), td.getDataType());
                carriers.add(td);
            }
        }

        int sigs = 0, sigBad = 0;
        String conv = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        for (Map.Entry<String, DataType> e : parser.getFunctions().entrySet()) {
            String name = e.getKey();
            if (!name.matches("func_[0-9A-F]{8}") || !(e.getValue() instanceof FunctionDefinition)) {
                continue;
            }
            Address a = toAddr(Long.parseLong(name.substring(5), 16));
            Function f = getFunctionAt(a);
            if (f == null) {
                f = createFunction(a, name);
            }
            if (f == null) {
                sigBad++;
                continue;
            }
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(a,
                    (FunctionDefinition) e.getValue(), SourceType.USER_DEFINED);
            if (cmd.applyTo(currentProgram, monitor)) {
                f.setCallingConvention(conv);
                sigs++;
            } else {
                sigBad++;
            }
        }

        // Globals, smallest first: a struct that covers smaller labelled fields wins.
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        List<Object[]> globals = new ArrayList<>();
        int merged = 0;
        for (Map.Entry<String, TreeMap<Integer, DataType>> e : views.entrySet()) {
            String name = e.getKey();
            long addr = Long.parseLong(name.substring(2), 16);
            List<DataType> vs = new ArrayList<>(e.getValue().values());
            DataType dt = vs.get(0);
            if (dt instanceof Structure) {
                dt = merge(dtm, name, addr, vs, views, labels);
                merged++;
            }
            if (dt instanceof Array arr && arr.getNumElements() <= 1 && arr.getElementLength() > 0) {
                // `T D[]`: as many elements as fit before the next label (at most 64 KB).
                Long next = labels.higherKey(addr);
                long gap = next == null ? 0x10000 : Math.min(next - addr, 0x10000);
                int n = (int) Math.max(1, gap / arr.getElementLength());
                dt = new ArrayDataType(arr.getDataType(), n, arr.getElementLength());
            }
            if (dt.getLength() > 0) {
                globals.add(new Object[] { addr, name, dt });
            }
        }
        globals.sort((x, y) -> Integer.compare(((DataType) x[2]).getLength(), ((DataType) y[2]).getLength()));
        int typed = 0, typeBad = 0;
        for (Object[] g : globals) {
            Address a = toAddr((Long) g[0]);
            if (!mem.contains(a)) {
                typeBad++;
                if (errs.size() < 10) {
                    errs.add(g[1] + " is outside the program's memory");
                }
                continue;
            }
            try {
                DataUtilities.createData(currentProgram, a, (DataType) g[2], -1,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                if (st.getGlobalSymbol((String) g[1], a) == null) {
                    st.createLabel(a, (String) g[1], SourceType.USER_DEFINED).setPrimary();
                }
                typed++;
            } catch (Exception ex) {
                typeBad++;
                if (errs.size() < 10) {
                    errs.add(g[1] + " " + ((DataType) g[2]).getName() + "  <- " + ex.getMessage());
                }
            }
        }

        int renamed = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getSymbol().getSource() == SourceType.DEFAULT) {
                f.setName(String.format("func_%08X", f.getEntryPoint().getOffset()), SourceType.USER_DEFINED);
                renamed++;
            }
        }

        // The dk_G typedefs only carried the globals' types.
        currentProgram.getDataTypeManager().remove(carriers, monitor);

        int conflicts = 0;
        for (java.util.Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext();) {
            if (it.next().getName().contains(".conflict")) {
                conflicts++;
            }
        }
        println("dk-types: " + conflicts + " duplicate (.conflict) types in the project");
        println(String.format("dk-types: %d pieces failed to parse; %d prototypes applied (%d not); "
                + "%d globals typed (%d not, %d merged structs); %d labels; %d functions renamed; %d of %d switch tables",
                bad, sigs, sigBad, typed, typeBad, merged, named, renamed, jts, switches.size()));
        for (String err : errs) {
            println("dk-types: " + err);
        }
    }

    private static final Pattern PAD = Pattern.compile("(?i)^_*(pad|unk|fill)");

    /** One struct from every struct view of a global: each view's named (not padding)
     *  fields where they don't overlap an earlier view's, plus a field for each labelled
     *  global inside it that has a plain type of its own. */
    private Structure merge(DataTypeManager dtm, String name, long addr, List<DataType> vs,
            TreeMap<String, TreeMap<Integer, DataType>> views, TreeMap<Long, String> labels) {
        int size = 0;
        for (DataType v : vs) {
            if (v instanceof Structure) {
                size = Math.max(size, v.getLength());
            }
        }
        StructureDataType m = new StructureDataType(new CategoryPath("/dk"), name + "_t", size, dtm);
        boolean[] used = new boolean[size];
        for (DataType v : vs) {
            if (!(v instanceof Structure s)) {
                continue;
            }
            for (DataTypeComponent c : s.getDefinedComponents()) {
                String fn = c.getFieldName();
                if (c.isBitFieldComponent() || fn == null || PAD.matcher(fn).find()) {
                    continue;
                }
                place(m, used, c.getOffset(), c.getDataType(), c.getLength(), fn);
            }
        }
        for (Map.Entry<Long, String> l : labels.subMap(addr + 1, addr + size).entrySet()) {
            TreeMap<Integer, DataType> lv = views.get(l.getValue());
            DataType t = lv == null ? null : lv.firstEntry().getValue();
            if (t != null && !(t instanceof Composite) && !(t instanceof Array) && t.getLength() > 0) {
                place(m, used, (int) (l.getKey() - addr), t, t.getLength(), l.getValue());
            }
        }
        return (Structure) dtm.addDataType(m, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private static void place(StructureDataType m, boolean[] used, int off, DataType t, int len, String fn) {
        if (len <= 0 || off < 0 || off + len > used.length) {
            return;
        }
        for (int i = off; i < off + len; i++) {
            if (used[i]) {
                return;
            }
        }
        m.replaceAtOffset(off, t, len, fn, null);
        for (int i = off; i < off + len; i++) {
            used[i] = true;
        }
    }
}
