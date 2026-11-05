package net.mullvad.talpid

import android.os.Build

/** Test-only SDK staging for the SDK jar's final field. Always restore in cleanup. */
internal object LocalCaptureTestPlatform {
    fun setSdk(value: Int) {
        val field = Build.VERSION::class.java.getDeclaredField("SDK_INT")
        val type = Class.forName("sun.misc.Unsafe")
        val unsafe = type.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
        val base =
            type
                .getMethod("staticFieldBase", java.lang.reflect.Field::class.java)
                .invoke(unsafe, field)
        val offset =
            type
                .getMethod("staticFieldOffset", java.lang.reflect.Field::class.java)
                .invoke(unsafe, field)
        type
            .getMethod(
                "putIntVolatile",
                Any::class.java,
                Long::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
            )
            .invoke(unsafe, base, offset, value)
        check(field.getInt(null) == value)
    }
}
