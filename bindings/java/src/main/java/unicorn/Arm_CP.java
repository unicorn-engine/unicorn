package unicorn;

/** ARM coprocessor register for MRC, MCR, MRRC, MCRR */
public class Arm_CP {
    public int cp, is64, sec, crn, crm, opc1, opc2;
    public long val;

    public Arm_CP(int cp, int is64, int sec, int crn, int crm, int opc1,
            int opc2) {
        this(cp, is64, sec, crn, crm, opc1, opc2, 0);
    }

    public Arm_CP(int cp, int is64, int sec, int crn, int crm, int opc1,
            int opc2, long val) {
        this.cp = cp;
        this.is64 = is64;
        this.sec = sec;
        this.crn = crn;
        this.crm = crm;
        this.opc1 = opc1;
        this.opc2 = opc2;
        this.val = val;
    }

    @Override
    public String toString() {
        return "Arm_CP [cp=" + cp + ", is64=" + is64 + ", sec=" + sec +
            ", crn=" + crn + ", crm=" + crm + ", opc1=" + opc1 + ", opc2=" +
            opc2 + ", val=" + val + "]";
    }
}
