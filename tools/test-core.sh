#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
: "${JUNIT_JAR:?Set JUNIT_JAR to junit-4.13.2.jar}"
: "${HAMCREST_JAR:?Set HAMCREST_JAR to hamcrest-core-1.3.jar}"
task_test="$project_dir/app/build/core-tests"
mkdir -p "$task_test"
find "$project_dir/app/src/main/java/info/hen14/applepen/core" "$project_dir/app/src/test/java" -name '*.java' > "$task_test/sources.txt"
java com.sun.tools.javac.Main -encoding UTF-8 -classpath "$JUNIT_JAR:$HAMCREST_JAR" -d "$task_test" @"$task_test/sources.txt"
java -classpath "$task_test:$project_dir/app/src/test/resources:$JUNIT_JAR:$HAMCREST_JAR" org.junit.runner.JUnitCore info.hen14.applepen.core.CoreTest info.hen14.applepen.core.ReleaseTest info.hen14.applepen.core.ProtocolTest info.hen14.applepen.core.ApplicabilityTest
