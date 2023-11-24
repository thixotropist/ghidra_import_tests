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
 */
public class IgcTests extends TestRunner {
    Memory memory;
    AddressFactory addressFactory;
    int spaceID;

    private void relocationTests() throws Exception {

        // R_RISCV_BRANCH, type 0x10, a single instruction PC-relative offset
        matchInt("R_RISCV_BRANCH relocation", 0x100eec, 0x0206d563);

        // R_RISCV_CALL, type 0x12, PC-relative with signed (auipc+jalr consecutive instruction pair)
        //matchInt("R_RISCV_CALL relocation word 1", 0x11046c, 0x0000C097);
        //matchInt("R_RISCV_CALL relocation word 2", 0x110470, 0xD84080E7);
    
        // R_RISCV_JAL, type 0x11
        matchInt("R_RISCV_JAL", 0x108ca0, 0xd8dfe06f);

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is positive
        matchInt("R_RISCV_PCREL_HI20 1/2", 0x10fa18, 0x0000c617);

        // R_RISCV_PCREL_HI20, type 0x17
        //   Where the corresponding R_RISCV_PCREL_LO12_I offset is negative
        matchInt("R_RISCV_PCREL_HI20 2/2", 0x10b55c, 0xffffc597);

        // R_RISCV_PCREL_LO12_I, type 0x18
        matchInt("R_RISCV_PCREL_LO12_I", 0x105154, 0xd5860613);

        // R_RISCV_64, type 0x02
        matchLong("R_RISCV_64", 0x100900, 0x0000000000106fccL);

        // R_RISCV_RVC_BRANCH, type 0x2c
        matchShort("R_RISCV_RVC_BRANCH", 0x10f552, 0xd161);

        //R_RISCV_ADD32, type 0x23
        matchInt("R_ADD_32", 0x11690c, 0xffff1df0);
        
        //R_RISCV_ADD64, type 0x24
        matchLong("R_RISCV_ADD64", 0x116be0, 0x000000000001af8L);
        
        //R_RISCV_SUB32, type 0x27
        matchInt("R_SUB_32", 0x116dcc, 0xffff8ac4);
        
        // R_RISCV_SUB64, type 0x28
        matchLong("R_RISCV_ADD64", 0x116b50, 0x000000000001958L);

        // R_RISCV_RVC_JUMP, type 0x02d
        matchShort("R_RISCV_RVC_JUMP", 0x1016da, 0xbfc1);
    }

    @Override
    public void run() throws Exception {
        String jsonTestOutputFile;
        String[] args = getScriptArgs();
        if (args.length > 0) {
            jsonTestOutputFile = getScriptArgs()[0];
        }
        else {
            jsonTestOutputFile = "/tmp/igc_ko.json";
        }
        println("Starting IGC import tests, with output to " + jsonTestOutputFile);
        this.init();
        relocationTests();
        this.writeTestResults(jsonTestOutputFile);
        println("Ending IGC import tests");
    }
}
