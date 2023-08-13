
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;


public class KernelImport extends GhidraScript {
 
    @Override
    public void run() throws Exception {
        final long LOAD_OFFSET = 0x80000000L;
        final long FUNC_ADDR_PANIC = 0x0000000080b6b188L;
        final long FUNC_ADDR__PRINTK = 0x0000000080b6bf44L;

        println("Invoked pre-analysis Ghidra Script");
        Memory mem = currentProgram.getMemory();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter();
        MemoryBlock[] blocks = mem.getBlocks();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        int spaceID = addressFactory.getDefaultAddressSpace().getSpaceID();

        for (MemoryBlock b : blocks) {
            long start = b.getStart().getOffset();
            Address newStart = b.getStart().add(LOAD_OFFSET);
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
        Address panicAddr = addressFactory.getAddress(spaceID, FUNC_ADDR_PANIC);
        println("identifying panic function at 0x" + Long.toHexString(panicAddr.getOffset()));
        createFunction(addressFactory.getAddress(spaceID, FUNC_ADDR_PANIC), "panic");
        //createFunction(addressFactory.getAddress(spaceID, FUNC_ADDR__PRINTK), "_printk");
    }
}