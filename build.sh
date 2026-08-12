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

# fetch deps once if missing (re-fetch if a prior download left a 0-byte/partial file)
[ -s "$MONTOYA" ] || curl -s -o "$MONTOYA" https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2025.5/montoya-api-2025.5.jar
[ -s "$JSON" ]    || curl -s -o "$JSON"    https://repo1.maven.org/maven2/org/json/json/20250107/json-20250107.jar

# cache org.json extraction. Guard on an ACTUAL class (not just the dir): /tmp gets cleaned and a stale empty
# org/json/ dir would otherwise make us skip re-extraction and silently ship a thin jar → NoClassDefFoundError.
if [ ! -f "$CACHE/org/json/JSONArray.class" ]; then
  rm -rf "$CACHE"; mkdir -p "$CACHE"
  (cd "$CACHE" && jar xf "$JSON" && rm -rf META-INF)
fi

rm -rf "$OUT"; mkdir -p "$OUT" target
javac --release 17 -cp "$MONTOYA:$JSON" -d "$OUT" $(find src/main/java -name '*.java')
cp -R "$CACHE"/. "$OUT"/
cp -R src/main/resources/* "$OUT"/
jar --create --file "$JAR" -C "$OUT" .

# fail loudly if org.json didn't make it in — the runtime error is a cryptic NoClassDefFoundError otherwise.
if ! unzip -l "$JAR" | grep -q 'org/json/JSONArray.class'; then
  echo "!! BUILD BROKEN: org.json not bundled in $JAR (stale cache?). Run: rm -rf $CACHE $JSON && ./build.sh" >&2
  exit 1
fi
echo "built $JAR ($(unzip -l "$JAR" | grep -c 'org/json/.*\.class') org.json classes bundled)"
