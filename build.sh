#!/usr/bin/env bash
# Builds netanomaly.jar with just the JDK (no Maven needed). Requires Java 17+.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build && mkdir -p build/classes
javac --release 17 -d build/classes $(find src/main/java -name '*.java')
jar --create --file netanomaly.jar --main-class netanomaly.Main -C build/classes .
echo "Built netanomaly.jar  ->  java -jar netanomaly.jar --help"
