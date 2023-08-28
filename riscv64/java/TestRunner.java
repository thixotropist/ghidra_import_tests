import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

class TestResult {
    String description;
    boolean passed;
    String addr;
    String expecting;
    String observed;

    TestResult(String descr, boolean passValue, long addrValue, String expectedValue, String observedValue) {
        description = descr;
        passed = passValue;
        addr = String.format("0x%08x", addrValue);
        expecting = expectedValue;
        observed = observedValue;
    }
}

public class TestRunner extends GhidraScript {
    Memory memory;
    AddressFactory addressFactory;
    int spaceID;
    ArrayList<TestResult> testResults;

    public void init() {
        this.memory = currentProgram.getMemory();
        this.addressFactory = currentProgram.getAddressFactory();
        this.spaceID = addressFactory.getDefaultAddressSpace().getSpaceID();
        this.testResults = new ArrayList<TestResult>();
    }

    @Override
    public void run() throws Exception {
        // Don't run this, run a derived class
    }

    private void add(TestResult result) {
        testResults.add(result);
    }

    public void matchLong(String description, long addr, long expectedValue) throws Exception {
        long observedValue = memory.getLong(addressFactory.getAddress(spaceID, addr));
        testResults.add(new TestResult(
                description,
                observedValue == expectedValue,
                addr,
                String.format("0x%016x", expectedValue),
                String.format("0x%016x", observedValue)));
    }

    public void matchInt(String description, long addr, int expectedValue) throws Exception {
        int observedValue = memory.getInt(addressFactory.getAddress(spaceID, addr));
        testResults.add(new TestResult(
                description,
                observedValue == expectedValue,
                addr,
                String.format("0x%08x", expectedValue),
                String.format("0x%08x", observedValue)));
    }

    public void matchShort(String description, long addr, int expectedValue) throws Exception {
        // TODO: there has got to be a better way to handle unsigned short comparison...
        short observedValue = memory.getShort(addressFactory.getAddress(spaceID, addr));
        testResults.add(new TestResult(
                description,
                (0xffff & observedValue) == (0xffff & expectedValue),
                addr,
                String.format("0x%04x", expectedValue),
                String.format("0x%04x", observedValue)));
    }

    public void skipTest(String description, long addr) throws Exception {
        testResults.add(new TestResult(
            "SKIPPED: " + description,
            true,
            addr,
            "NA",
            "NA"));
    }

    public void writeTestResults(String outFileName) {
        FileWriter resultsFile = null;
        BufferedWriter resultsWriter = null;
        try {
            resultsFile = new FileWriter(outFileName);
            resultsWriter = new BufferedWriter(resultsFile);
            resultsWriter.write("[ ");
            int testCounter = 0;
            ;
            for (TestResult r : testResults) {
                if (testCounter != 0) {
                    resultsWriter.write(", ");
                }
                testCounter++;
                resultsWriter.write(String.format("{\"description\" : \"%s\",%n", r.description));
                resultsWriter.write(String.format("\"passed\" : \"%s\",%n", r.passed));
                resultsWriter.write(String.format("\"addr\" : \"%s\",%n", r.addr));
                resultsWriter.write(String.format("\"expected\" : \"%s\",%n", r.expecting));
                resultsWriter.write(String.format("\"observed\" : \"%s\"}%n", r.observed));
            }
            resultsWriter.write("]");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (resultsWriter != null) {
                    resultsWriter.flush();
                    resultsWriter.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
