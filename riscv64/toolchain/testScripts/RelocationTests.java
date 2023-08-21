import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

/**
 * Test various relocations on a riscv64 object file compiled with -pie.
 */
public class RelocationTests extends GhidraScript {
    private int relocationTests(Program program) throws Exception {
        Memory memory = program.getMemory();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        int spaceID = addressFactory.getDefaultAddressSpace().getSpaceID();
        int errCount = 0;
        int passedCount = 0;
        int skippedCount = 0;
        int instruction;
        int data;
        long longData;
        int instructionNext;
        short condensedInstruction;

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is positive
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x100004));
        if (instruction == 0x00001517) {
            println("Passed: R_RISCV_PCREL_HI20 at 0x100004");
            passedCount += 1;
        } else {
            println("Failed: R_RISCV_PCREL_HI20 at 0x100004, should be 0x00001517" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is negative
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x10000c));
        if (instruction == 0x00002797) {
            println("Passed: R_RISCV_PCREL_HI20 at 0x10000c");
            passedCount += 1;
        } else {
            println("Failed: R_RISCV_PCREL_HI20 at 0x10000c, should be 0x00002797" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_PCREL_LO12_I, type 0x18
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x100008));
        if (instruction == 0x04c50513) {
            println("Passed: R_RISCV_PCREL_LO12_I at 0x100008");
            passedCount += 1;
        } else {
            println("Failed: R_RISCV_PCREL_LO12_I at 0x100008, should be : 0x04c50513" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_PCREL_LO12_S, type 0x19
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x100010));
        if (instruction == 0x840782a3) {
            println("Passed: R_RISCV_PCREL_LO12_S at 0x1000010");
            passedCount += 1;
        } else {
            println("Failed: R_RISCV_PCREL_LO12_S at 0x1000010, should be : 0x840782a3" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_TPREL_HI20, type 0x1d
        data = memory.getInt(addressFactory.getAddress(spaceID, 0x100020));     
        println("Skipped: R_RISCV_TPREL_HI20 at 0x100020, not implemented");
        skippedCount += 1;

        // R_RISCV_TPREL_LO12_I, type 0x1e
        data = memory.getInt(addressFactory.getAddress(spaceID, 0x100030));
        println("Skipped: R_RISCV_TPREL_LO12_I at 0x100030, not implemented");
        skippedCount += 1;

        // R_RISCV_TPREL_ADD, type 0x20
        data = memory.getInt(addressFactory.getAddress(spaceID, 0x100024));
        println("Skipped: R_RISCV_TPREL_ADD at 0x100024, not implemented");
        skippedCount += 1;
        
        println("Summary: " + passedCount + " tests passed, " + errCount + " tests failed, " + skippedCount + " tests skipped");
        return errCount;
    }

    @Override
    public void run() throws Exception {
        println("Starting IGC import tests");
        int errorCount = relocationTests(currentProgram);
        if (errorCount == 0) {
            println("Relocation Tests Pass");
        }
        else {
            println("Relocation Test Failures: " + errorCount);
        }
        println("Ending Relocation import tests");
    }
}
