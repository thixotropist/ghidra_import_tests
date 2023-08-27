import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

/**
 * Test the import of a C object file using various relocation types. 
 * Output is in the form of a JSON file that our Python integration test script can process.

 */
public class RelocationTestImport extends TestRunner {
    Memory memory;
    AddressFactory addressFactory;
    int spaceID;

    private void relocationTests() throws Exception {

        // R_RISCV_PCREL_HI20, 0x17
        matchInt("R_RISCV_PCREL_HI20 relocation", 0x100004, 0x00001517);

        // R_RISCV_LO12_I, type 0x18
        matchInt("R_RISCV_LO12_I relocation word 1", 0x100008, 0x04c50513);
    
        // R_RISCV_LO12_S, type 0x19
        matchInt("R_RISCV_LO12_S", 0x100010, 0x840782a3);

        // R_RISCV_CALL_PLT, type 0x13
        matchInt("R_RISCV_CALL_PLT 1/2", 0x100018, 0x00003097);
        matchInt("R_RISCV_CALL_PLT 1=2/2", 0x10001c, 0xfe8080e7);

        // R_RISCV_TPREL_HI20, type 0x1d
        // unimplemented!    
        skipTest("R_RISCV_TPREL_HI20", 0x100020);

        // R_RISCV_TPREL_ADD, type 0x20
        // unimplemented!    
        skipTest("R_RISCV_TPREL_ADD", 0x100024);

        // R_RISCV_TPREL_LO12_I, type 0x1e
        // unimplemented!    
        skipTest("R_RISCV_TPREL_LO12_I", 0x100028);
    }

    @Override
    public void run() throws Exception {
        String jsonTestOutputFile = getScriptArgs()[0];
        println("Starting import tests, with output to " + jsonTestOutputFile);
        this.init();
        relocationTests();
        this.writeTestResults(jsonTestOutputFile);
        println("Ending import tests");
    }
}
