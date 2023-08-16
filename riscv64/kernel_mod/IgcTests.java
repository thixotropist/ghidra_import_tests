import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

/**
 * Test the import of a RISCV-64 Linux kernel module.  These modules show many types of relocation codes
 * not found in basic user-space executables.
 */
public class IgcTests extends GhidraScript {
    private int relocationTests(Program program) throws Exception {
        Memory memory = program.getMemory();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        int spaceID = addressFactory.getDefaultAddressSpace().getSpaceID();
        int errCount = 0;
        int instruction;
        int data;
        long longData;
        int instructionNext;
        short condensedInstruction;

        // R_RISCV_BRANCH, type 0x10, a single instruction PC-relative offset
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x1070f4));
        if (instruction != 0x640C0E63) {
            println("Error: R_RISCV_BRANCH at 0x1070F4, should be 0x640C0E63: 0x" + 
                String.format("%1$08X", instruction));
            errCount += 1;
        }

        // R_RISCV_CALL, type 0x12, PC-relative with signed (auipc+jalr consecutive instruction pair)
        // TODO: the offset is generated with signed addition, so we should test with several instances.
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x11046c));
        instructionNext = memory.getInt(addressFactory.getAddress(spaceID, 0x110470));
        if ((instruction != 0x0000C097) || (instructionNext != 0xD84080E7)) {
            println("Error: R_RISCV_CALL at 0x11046C, should be 0x0000C097 0xD84080E7: 0x" +
                String.format("%1$08X", instruction) +
                    " 0x" + String.format("%1$08X", instructionNext));
            errCount += 1;
        }

        // R_RISCV_RVC_BRANCH, type 0x2c
        condensedInstruction = memory.getShort(addressFactory.getAddress(spaceID, 0x107160));
        // Note that we must sign-extend short constants like 0xcf3d
        if (condensedInstruction != 0xFFFFCF3D) {
            println("Error: R_RISCV_RVC_BRANCH at 0x107160, should be 0xCF3D: 0x" +
                String.format("%1$04X", condensedInstruction));
            errCount += 1;
        }

        // R_RISCV_JAL, type 0x11
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x1072d6));
        if (instruction != 0x11C0106F) {
            println("Error: R_RISCV_JAL at 0x1072D6, should be 0x11C0106F" +
                String.format("%1$08X", instruction));
            errCount += 1;    
        }

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is positive
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x107186));
        if (instruction != 0x0000F797) {
            println("Error: R_RISCV_PCREL_HI20 at 0x107186, should be 0x0000F797" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is negative
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x107652));
        if (instruction != 0x00015797) {
            println("Error: R_RISCV_PCREL_HI20 at 0x107652, should be 0x00015797" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_PCREL_LO12_I, type 0x18
        instruction = memory.getInt(addressFactory.getAddress(spaceID, 0x10718a));
        if (instruction != 0xCA278793) {
            println("Error: R_RISCV_PCREL_LO12_I at 0x10718a, should be : 0xCA278793" +
                String.format("%1$08X", instruction));
            errCount += 1;  
        }

        // R_RISCV_64, type 0x02
        longData = memory.getLong(addressFactory.getAddress(spaceID, 0x1006c0));
        if (longData != 0x0000000000100E44) {
            println("Error: R_RISCV_64 at 0x1006C0, should be 0x0000000000100E44: " +
                String.format("%1$016X", longData));
            errCount += 1;  
        }

        //R_RISCV_ADD32, type 0x23
        data = memory.getInt(addressFactory.getAddress(spaceID, 0x115a70));
        if (data != 0xFFFF8EFA) {
            println("Error: R_ADD_32 at 0x115A70, should be 0xFFFF8EFA: " +
                String.format("%1$08X", data));
            errCount += 1;  
        }
        
        //R_RISCV_ADD64, type 0x24
        longData = memory.getLong(addressFactory.getAddress(spaceID, 0x1156B8));
        if (longData != 0x000000000000E48) {
            println("Error: R_RISCV_ADD64 at 0x1156B8, should be : 0x000000000000E48" +
                String.format("%1$016X", longData));
            errCount += 1;  
        }
        
        //R_RISCV_SUB32, type 0x27
        data = memory.getInt(addressFactory.getAddress(spaceID, 0x115ad4));
        if (data != 0xFFFF92BA) {
            println("Error: R_SUB32 at 0x115AD4, should be 0xFFFF92BA: " +
                String.format("%1$08X", data));
            errCount += 1;  
        }
        
        // R_RISCV_SUB64, type 0x28
        longData = memory.getLong(addressFactory.getAddress(spaceID, 0x115638));
        if (longData != 0x000000000000BB8) {
            println("Error: R_RISCV_SUB64 at 0x115638, should be : 0x000000000000BB8" +
                String.format("%1$016X", longData));
            errCount += 1;  
        }

        // R_RISCV_RVC_JUMP, type 0x02d
        condensedInstruction = memory.getShort(addressFactory.getAddress(spaceID, 0x106842));
        // Note that we must sign-extend short constants like 0xcf3d
        if (condensedInstruction != 0xFFFFB5E9) {
            println("Error: R_RISCV_RVC_BRANCH at 0x106842, should be 0xB5E9: 0x" +
                String.format("%1$04X", condensedInstruction));
            errCount += 1;
        }

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
        println("Ending IGC import tests");
    }
}
