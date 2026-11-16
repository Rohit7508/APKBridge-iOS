// APKBridge conformance reference (JVM baseline).
// Each method mirrors the logic of one DEX fixture. For the integer/array/
// control-flow subset tested, JVM and Dalvik semantics agree, so the JVM
// result is a valid independent oracle for the interpreter.
// (Confirming against real Dalvik on a device additionally needs the Android
//  SDK: `d8 Reference.class` + `adb shell` — commands documented, not run here.)
public class Reference {
    static int arith()  { return (7 + 5) * 3 - 6 / 2; }       // 33
    static int sumTo(int n) { int acc = 0; for (int i = 1; i <= n; i++) acc += i; return acc; }
    static int add(int a, int b) { return a + b; }
    static int invoke() { return add(20, 22); }               // 42
    static int addA(int x) { return x + 100; }                // cross-dex library
    static int crossdexA() { return addA(0); }                // standalone = 100
    static int crossdexB() { return addA(5); }                // = 105
    static int object() { Point p = new Point(); p.x = 7; return p.x; } // 7
    static int array()  { int[] a = {10, 20, 12}; return a[0] + a[1] + a[2] + a.length; } // 45
    static int exception() { try { throw new RuntimeException(); } catch (RuntimeException e) { return 99; } }

    static class Point { int x; }

    public static void main(String[] args) {
        System.out.println("arith=" + arith());
        System.out.println("loop=" + sumTo(10));
        System.out.println("invoke=" + invoke());
        System.out.println("object=" + object());
        System.out.println("array=" + array());
        System.out.println("exception=" + exception());
        System.out.println("crossdexA=" + crossdexA());
        System.out.println("crossdexB=" + crossdexB());
    }
}
