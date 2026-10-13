#!/usr/bin/env bash
set -euo pipefail
# Dependency-free SDK build for restricted environments. Normal development uses Gradle.
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
task_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$task_sdk" ]]; then echo 'Set ANDROID_HOME to an installed Android SDK.' >&2; exit 1; fi
task_tools="$task_sdk/build-tools/36.0.0"
task_android="$task_sdk/platforms/android-36/android.jar"
task_build="$project_dir/app/build/manual"
rm -rf "$task_build"
mkdir -p "$task_build/classes" "$task_build/resources" "$task_build/generated" "$task_build/dex"
"$task_tools/aapt2" compile --dir "$project_dir/app/src/main/res" -o "$task_build/resources"
mapfile -t task_resources < <(find "$task_build/resources" -name '*.flat' -print)
python3 - "$project_dir/app/src/main/AndroidManifest.xml" "$task_build/AndroidManifest.xml" <<'PY'
import sys
text = open(sys.argv[1]).read().replace('<manifest ', '<manifest package="info.hen14.applepen" ', 1)
open(sys.argv[2], 'w').write(text)
PY
"$task_tools/aapt2" link -o "$task_build/unsigned.apk" -I "$task_android" \
  --manifest "$task_build/AndroidManifest.xml" --java "$task_build/generated" --debug-mode \
  --min-sdk-version 30 --target-sdk-version 36 --version-code 1 --version-name 0.1.0 \
  "${task_resources[@]}"
find "$project_dir/app/src/main/java" "$task_build/generated" -name '*.java' -print > "$task_build/sources.txt"
java com.sun.tools.javac.Main -encoding UTF-8 -source 17 -target 17 -classpath "$task_android" -d "$task_build/classes" @"$task_build/sources.txt"
java sun.tools.jar.Main --create --file "$task_build/classes.jar" -C "$task_build/classes" .
"$task_tools/d8" --min-api 30 --lib "$task_android" --output "$task_build/dex" "$task_build/classes.jar"
python3 - "$task_build/unsigned.apk" "$task_build/dex" <<'PY'
import pathlib, sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'a', compression=zipfile.ZIP_DEFLATED) as apk:
    for dex in pathlib.Path(sys.argv[2]).glob('*.dex'):
        apk.write(dex, dex.name)
PY
"$task_tools/zipalign" -f -p 4 "$task_build/unsigned.apk" "$task_build/aligned.apk"
task_key="$project_dir/app/build/applepen-debug.keystore"
if [[ ! -f "$task_key" ]]; then
  keytool -genkeypair -keystore "$task_key" -storepass android -keypass android -alias androiddebugkey \
    -dname 'CN=Android Debug,O=Android,C=US' -keyalg RSA -keysize 2048 -validity 10000 >/dev/null 2>&1
fi
"$task_tools/apksigner" sign --ks "$task_key" --ks-key-alias androiddebugkey \
  --ks-pass pass:android --key-pass pass:android --out "$task_build/ApplePen-v0.1.0.apk" "$task_build/aligned.apk"
"$task_tools/apksigner" verify "$task_build/ApplePen-v0.1.0.apk"
echo "$task_build/ApplePen-v0.1.0.apk"
