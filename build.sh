#!/bin/bash
# Fast local build (no Maven). Caches the org.json extraction across runs so each
# rebuild is just javac (~1-2s) + jar assembly instead of re-unzipping ~600 classes.
set -e
cd "$(dirname "$0")"

MONTOYA=/tmp/montoya-2025.5.jar
JSON=/tmp/json-20250107.jar
CACHE=/tmp/arf-jsoncache        # extracted org.json classes, cached
OUT=/tmp/aisbuild               # per-build compile output
JAR=target/ai-scanner-0.1.0.jar

# fetch deps once if missing
[ -f "$MONTOYA" ] || curl -s -o "$MONTOYA" https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2025.5/montoya-api-2025.5.jar
[ -f "$JSON" ]    || curl -s -o "$JSON"    https://repo1.maven.org/maven2/org/json/json/20250107/json-20250107.jar

# cache org.json extraction (only the first time)
if [ ! -d "$CACHE/org" ]; then
  rm -rf "$CACHE"; mkdir -p "$CACHE"
  (cd "$CACHE" && jar xf "$JSON" && rm -rf META-INF)
fi

rm -rf "$OUT"; mkdir -p "$OUT" target
javac --release 17 -cp "$MONTOYA:$JSON" -d "$OUT" $(find src/main/java -name '*.java')
cp -R "$CACHE"/. "$OUT"/
cp -R src/main/resources/* "$OUT"/
jar --create --file "$JAR" -C "$OUT" .
echo "built $JAR"
