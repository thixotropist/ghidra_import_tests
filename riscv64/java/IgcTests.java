
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

/**
 * Test the import of a RISCV-64 Linux kernel module.  These modules show many types of relocation codes
 * not found in basic user-space executables.  Output is in the form of a JSON file that our Python integration test
 * script can process.
 * 
 * TODO: Move the match and formatting code into a sharable Java class
 * TODO: Find a better way to create a temporary file here to be consumed by the integration test.
 */
public class IgcTests extends TestRunner {
    Memory memory;
    AddressFactory addressFactory;
    int spaceID;

    private void relocationTests() throws Exception {

        // R_RISCV_BRANCH, type 0x10, a single instruction PC-relative offset
        matchInt("R_RISCV_BRANCH relocation", 0x1070f4, 0x640C0E63);

        // R_RISCV_CALL, type 0x12, PC-relative with signed (auipc+jalr consecutive instruction pair)
        matchInt("R_RISCV_CALL relocation word 1", 0x11046c, 0x0000C097);
        matchInt("R_RISCV_CALL relocation word 2", 0x110470, 0xD84080E7);
    
        // R_RISCV_JAL, type 0x11
        matchInt("R_RISCV_JAL", 0x1072d6, 0x11C0106F);

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is positive
        matchInt("R_RISCV_PCREL_HI20 1/2", 0x107186, 0x0000F797);

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is negative
        matchInt("R_RISCV_PCREL_HI20 2/2", 0x107652, 0x00015797);

        // R_RISCV_PCREL_LO12_I, type 0x18
        matchInt("R_RISCV_PCREL_LO12_I", 0x10718a, 0xCA278793);

        // R_RISCV_64, type 0x02
        matchLong("R_RISCV_64", 0x1006c0, 0x0000000000100E44L);

        // R_RISCV_RVC_BRANCH, type 0x2c
        matchShort("R_RISCV_RVC_BRANCH", 0x107160, 0xCF3D);

        //R_RISCV_ADD32, type 0x23
        matchInt("R_ADD_32", 0x115a70, 0xFFFF8EFA);
        
        //R_RISCV_ADD64, type 0x24
        matchLong("R_RISCV_ADD64", 0x1156B8, 0x000000000000E48L);
        
        //R_RISCV_SUB32, type 0x27
        matchInt("R_SUB_32", 0x115ad4, 0xFFFF92BA);
        
        // R_RISCV_SUB64, type 0x28
        matchLong("R_RISCV_ADD64", 0x115638, 0x000000000000BB8L);

        // R_RISCV_RVC_JUMP, type 0x02d
        matchShort("R_RISCV_RVC_JUMP", 0x106842, 0xB5E9);
    }

    @Override
    public void run() throws Exception {
        String jsonTestOutputFile = getScriptArgs()[0];
        println("Starting IGC import tests, with output to " + jsonTestOutputFile);
        this.init();
        relocationTests();
        this.writeTestResults(jsonTestOutputFile);

        println("Ending IGC import tests");
    }
}
