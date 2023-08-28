import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import ghidra.program.model.listing.Program;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;

/**
 * @brief Import a vmlinux kernel as a binary file, relocate to 0xffffffff80000000, then apply
 * all symbols from the associated System.map file.
 */

public class KernelImport extends GhidraScript {

    public void importSyms(Program program, AddressFactory addressFactory, int spaceID) {
        String systemMapFile = "/tmp/ghidra_import_tests/System.map-6.0.10-300.0.riscv64.fc37.riscv64";
        SymbolTable st = program.getSymbolTable();
        BufferedReader reader;
        Pattern pattern = Pattern.compile("(?<addr>[a-f0-9]{16})\\s*(?<type>[TtDdRdBbRr])\\s(?<name>[\\w.]+)");
        try {
            reader = new BufferedReader(new FileReader(systemMapFile));
            String line = reader.readLine();
            long addr;
            while (line != null) {
                Matcher matcher = pattern.matcher(line);
                boolean matchFound = matcher.find();
                if (matchFound && (matcher.groupCount() == 3)) {
                    addr = Long.parseUnsignedLong(matcher.group("addr"),16);
                    String name = matcher.group("name");
                    String type = matcher.group("type").toLowerCase();
                    try {
                           st.createLabel(addressFactory.getAddress(spaceID, addr), name, ghidra.program.model.symbol.SourceType.IMPORTED);
                        }
                    catch (Exception e) {
                        e.printStackTrace();
                    }
                    if (type.equals("t")) {
                        //println("createFunction(" + Long.toHexString(addr) + ", " + name + ")");
                        Address funcAddr = addressFactory.getAddress(spaceID, addr);
                        int transactionID = program.startTransaction("Import function name");
                        disassemble(funcAddr);
                        createFunction(funcAddr, name);
                        program.endTransaction(transactionID, true);
                    }
                }
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
 
    @Override
    public void run() throws Exception {
        final long LOAD_OFFSET = 0xffffffff80000000L;
        println("Invoked pre-analysis Ghidra Script");
        Memory mem = currentProgram.getMemory();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter();
        MemoryBlock[] blocks = mem.getBlocks();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        int spaceID = addressFactory.getDefaultAddressSpace().getSpaceID();

        for (MemoryBlock b : blocks) {
            long start = b.getStart().getOffset();
            Address newStart = addressFactory.getAddress(spaceID, start | LOAD_OFFSET);
            println("Found block " + b.getName() + " starting at 0x" + Long.toHexString(start));
            int transactionID = currentProgram.startTransaction("Move sections");
            try {
                mem.moveBlock(b, newStart, monitor);
                start = b.getStart().getOffset();
                println("Moved block " + b.getName() + " to start at 0x" + Long.toHexString(start));
            }
            finally {
                currentProgram.endTransaction(transactionID, true);
            }
        }
        importSyms(currentProgram, addressFactory, spaceID);

    }
}