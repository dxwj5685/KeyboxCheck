#!/data/data/com.termux/files/usr/bin/bash
mkdir -p build/gen build/obj build/apk

# 编译 Java
ecj -d build/obj $(find src/main/java -name "*.java")

# 生成 Dex
dx --dex --output=build/apk/classes.dex build/obj/

# 打包 APK
aapt package -f -m \
  -I $PREFIX/share/android/android.jar \
  -M src/main/AndroidManifest.xml \
  -S src/main/res \
  -J build/gen \
  -F build/unsigned.apk build/apk/

# 对齐优化
zipalign -f 4 build/unsigned.apk build/KeyCheck.apk

echo -e "\n✅ 编译成功！路径：build/KeyCheck.apk"
