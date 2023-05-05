package tests;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

public class TestSamples {
    private final ByteArrayOutputStream outContent =
        new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @Before
    public void setUpStreams() {
        outContent.reset();
        System.setOut(new PrintStream(outContent));
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
    }

    @Test
    public void testArm() {
        samples.Sample_arm.test_arm();
        assertEquals("testArm",
            "Emulate ARM code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> R0 = 0x37\n" +
                ">>> R1 = 0x3456\n",
            outContent.toString());
    }
}
