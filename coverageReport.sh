#!/bin/sh
#
#
# Small helper script to produce a coverage report when executing the fuzz-model
# against the current corpus.
#

set -eu


# Build the fuzzer and fetch dependency-jars
./gradlew shadowJar getDeps


# extract jar-files of the schemaless metrics parser implementation
mkdir -p build/hash4jFiles
cd build/hash4jFiles

# then unpack the class-files
for i in `find ../runtime -name hash4j-*.jar`; do
  echo $i
  unzip -o -q $i
done

# remove one file which causes jacoco to fail
rm -f META-INF/versions/21/com/dynatrace/hash4j/hashing/UnsignedMultiplyUtil.class META-INF/versions/21/com/dynatrace/hash4j/internal/UnsignedMultiplyUtil.class

cd -


# Fetch JaCoCo Agent
test -f jacoco-0.8.13.zip || wget --continue https://repo1.maven.org/maven2/org/jacoco/jacoco/0.8.13/jacoco-0.8.13.zip
unzip -o jacoco-0.8.13.zip lib/jacocoagent.jar lib/jacococli.jar
mv lib/jacocoagent.jar lib/jacococli.jar build/
rmdir lib

mkdir -p build/jacoco


# Run Jazzer with JaCoCo-Agent to produce coverage information
./jazzer \
  --cp=build/libs/hash4j-fuzz-all.jar \
  --instrumentation_includes=com.dynatrace.** \
  --target_class=com.dynatrace.hash4j.fuzz.Fuzz \
  --nohooks \
  --jvm_args="-javaagent\\:build/jacocoagent.jar=destfile=build/jacoco/corpus.exec" \
  -rss_limit_mb=1024 \
  -runs=0 \
  corpus

./jazzer \
  --cp=build/libs/hash4j-fuzz-all.jar \
  --instrumentation_includes=com.dynatrace.** \
  --target_class=com.dynatrace.hash4j.fuzz.SimHashFuzz \
  --nohooks \
  --jvm_args="-javaagent\\:build/jacocoagent.jar=destfile=build/jacoco/corpusSimHash.exec" \
  -rss_limit_mb=1024 \
  -runs=0 \
  corpusSimHash


# Finally create the JaCoCo report
java -jar build/jacococli.jar report build/jacoco/corpus.exec build/jacoco/corpusSimHash.exec \
 --classfiles build/hash4jFiles \
 --sourcefiles ../hash4j/src/main/java \
 --html build/reports/jacoco


echo All Done, report is at build/reports/jacoco/index.html
