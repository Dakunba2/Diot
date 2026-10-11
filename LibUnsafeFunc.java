// @category Analysis
// @description Recursively search dangerous function calls (up to 3 layers deep) - Java port of lib_unsafe_func.py

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

import java.sql.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.json.*;

public class LibUnsafeFunc extends GhidraScript {

    private static final int MAX_DEPTH = 3;
    private static final Set<String> DANGEROUS_FUNCS =
        new HashSet<>(Arrays.asList("system", "popen", "execve", "execl"));

    private Set<Address> visited = new HashSet<>();
    private Map<Address, List<List<Object[]>>> dangerousPaths = new HashMap<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("Usage: -postScript LibUnsafeFunc.java <lib_name> <base64_data> <db_path>");
            return;
        }
        String libName = args[0];
        String base64Data = args[1];
        String dbPath = args[2];

        // 注：原 lib_unsafe_func.py 对含 "Link" 的格式名重置 image base 为 0，
        // 但任何 ELF 都含 "Link" 子串，会把 main ELF 的地址平移导致函数找不到。
        // Windows/Ghidra 12 下保持 Ghidra 默认 image base，直接按符号表地址寻址。
        // String fileFormat = currentProgram.getExecutableFormat();
        // if (fileFormat != null && fileFormat.contains("Link")) {
        //     Address newBase = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        //     currentProgram.setImageBase(newBase, true);
        // }

        byte[] decoded = Base64.getDecoder().decode(base64Data);
        String jsonStr = new String(decoded, StandardCharsets.UTF_8);
        JSONObject data = new JSONObject(jsonStr);
        println("Parsed function address mappings, total: " + data.length());

        for (Iterator<String> it = data.keys(); it.hasNext(); ) {
            String funcName = it.next();
            String hexAddr = data.getString(funcName);
            try {
                Address addr = toAddr(Long.parseLong(hexAddr, 16));
                Function func = getFunctionAt(addr);
                if (func == null) {
                    println("[WARN] Function not found: " + funcName + " Address: " + hexAddr);
                    continue;
                }
                println("Analyzing function: " + funcName + " @ " + addr);
                visited.clear();
                traceDangerousCalls(func, 0, new ArrayList<Object[]>(), func);
            } catch (Exception e) {
                println("[ERROR] " + funcName + " " + hexAddr + " failed to process: " + e.getMessage());
            }
        }

        saveResultsToSQLite(dbPath, libName);
    }

    private void traceDangerousCalls(Function func, int depth, List<Object[]> chain, Function originFunc) {
        if (func == null || depth > MAX_DEPTH) {
            return;
        }
        visited.add(func.getEntryPoint());

        for (Object[] pair : getCallees(func)) {
            Address callAddr = (Address) pair[0];
            Function callee = (Function) pair[1];

            List<Object[]> newChain = new ArrayList<>(chain);
            newChain.add(new Object[]{func, callAddr, callee});

            if (DANGEROUS_FUNCS.contains(callee.getName())) {
                dangerousPaths.computeIfAbsent(originFunc.getEntryPoint(), k -> new ArrayList<>()).add(newChain);
            } else {
                if (!visited.contains(callee.getEntryPoint())) {
                    traceDangerousCalls(callee, depth + 1, newChain, originFunc);
                }
            }
        }
    }

    private List<Object[]> getCallees(Function func) {
        List<Object[]> result = new ArrayList<>();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(func.getBody(), true);
        while (instructions.hasNext()) {
            Instruction inst = instructions.next();
            if (inst.getFlowType().isCall()) {
                Reference[] refs = inst.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = getFunctionAt(ref.getToAddress());
                        if (callee != null) {
                            result.add(new Object[]{inst.getAddress(), callee});
                        }
                    }
                }
            }
        }
        return result;
    }

    private void saveResultsToSQLite(String dbPath, String libName) throws Exception {
        JSONArray resultData = new JSONArray();

        for (Map.Entry<Address, List<List<Object[]>>> e : dangerousPaths.entrySet()) {
            Address originAddr = e.getKey();
            Function originFunc = getFunctionAt(originAddr);
            if (originFunc == null) {
                continue;
            }
            for (List<Object[]> path : e.getValue()) {
                JSONArray steps = new JSONArray();
                for (Object[] step : path) {
                    Function caller = (Function) step[0];
                    Address callAddr = (Address) step[1];
                    Function callee = (Function) step[2];

                    JSONArray stepArr = new JSONArray();
                    JSONArray callerInfo = new JSONArray();
                    callerInfo.put(caller.getName());
                    callerInfo.put(caller.getEntryPoint().toString());
                    stepArr.put(callerInfo);
                    stepArr.put(callAddr.toString());
                    JSONArray calleeInfo = new JSONArray();
                    calleeInfo.put(callee.getName());
                    calleeInfo.put(callee.getEntryPoint().toString());
                    stepArr.put(calleeInfo);
                    steps.put(stepArr);
                }
                JSONObject item = new JSONObject();
                item.put("origin", originFunc.getName());
                item.put("origin_address", originFunc.getEntryPoint().toString());
                item.put("steps", steps);
                resultData.put(item);
            }
        }

        String jsonText = resultData.toString(2);

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath)) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE IF NOT EXISTS lib_unsafe_res_json (lib_file_name TEXT PRIMARY KEY, result_json TEXT)");
            }
            try (PreparedStatement pstmt = conn.prepareStatement(
                    "INSERT OR REPLACE INTO lib_unsafe_res_json(lib_file_name, result_json) VALUES (?, ?)")) {
                pstmt.setString(1, libName);
                pstmt.setString(2, jsonText);
                pstmt.executeUpdate();
            }
        }
        println("[INFO] result_data successfully written to SQLite");
    }
}
