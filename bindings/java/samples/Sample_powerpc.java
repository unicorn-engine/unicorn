import unicorn.*;

public class Sample_powerpc{

    public static final byte[] PPC_CODE = {
        0x39,0x20,0x00,0x04,       // li        r9, 4
        (byte)0x91,0x3F,0x00,0x08, // stw       r9, 8(r31)
        0x39,0x20,0x00,0x05,       // li        r9, 5
        (byte)0x91,0x3F,0x00,0x0C, // stw       r9, 0xC(r31)
        (byte)0x81,0x5F,0x00,0x08, // lwz       r10, 8(r31)
        (byte)0x81,0x3F,0x00,0x0C, // lwz       r9, 0xC(r31)
        0x7D,0x2A,0x4A,0x14        // add       r9, r10, r9
    };

    public static final int ADDRESS = 0x10000;
    public static final int DATA_ADDRESS = 0x00000;

    static void test_powerpc()
    {
        Unicorn u = new Unicorn(Unicorn.UC_ARCH_PPC, Unicorn.UC_MODE_32 | Unicorn.UC_MODE_BIG_ENDIAN);

        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);

        u.mem_map(DATA_ADDRESS, 4096, Unicorn.UC_PROT_READ | Unicorn.UC_PROT_WRITE);

        u.mem_write(ADDRESS, PPC_CODE);


        u.reg_write(Unicorn.UC_PPC_REG_GPR_31, DATA_ADDRESS);

        u.emu_start(ADDRESS, ADDRESS + PPC_CODE.length, 0, 0);

        Long r9  = (Long)u.reg_read(Unicorn.UC_PPC_REG_GPR_9);
        Long r10 = (Long)u.reg_read(Unicorn.UC_PPC_REG_GPR_10);

        System.out.print(String.format(">>> R9  = 0x%x\n", r9.intValue()));
        System.out.print(String.format(">>> R10 = 0x%x\n",r10.intValue()));

        u.close();
    }

    public static void main(String args[])
    {
        test_powerpc();
    }
}