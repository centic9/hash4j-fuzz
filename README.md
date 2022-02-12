This is a small project for fuzzing [hash4j](https://github.com/dynatrace-oss/hash4j) with the [jazzer](https://github.com/CodeIntelligenceTesting/jazzer/) fuzzing tool.

See [Fuzzing](https://en.wikipedia.org/wiki/Fuzzing) for a general description of the theory behind fuzzy testing.

Because Java uses a runtime environment which does not crash on invalid actions of an 
application (unless native code is invoked), Fuzzing of Java-based applications  
focuses on the following:

* verify if only expected exceptions are thrown
* verify any JNI or native code calls 
* find cases of unbounded memory allocations

hash4j does not use JNI or native code, therefore the fuzzing target mainly
tries to trigger unexpected exceptions and unbounded memory allocations.

# How to fuzz

Build the fuzzing target:

    ./gradlew shadowJar

Prepare a corpus of test-files (i.e. valid and invalid lines) and put them
into directory `corpus`

    mkdir corpus
    i=0;cat src/test/resources/samples.txt | while IFS='' read data;do echo "$data" > corpus/sample_$i.txt;i=$((i+1));done

You can add more documents to the corpus to help Jazzer in producing "nearly" 
proper queries which will improve fuzzing a lot. Slightly broken queries
seem to be a good seed for fuzzing as well.

Download Jazzer from the [releases page](https://github.com/CodeIntelligenceTesting/jazzer/releases), 
choose the latest version and select the file `jazzer-<os>-<version>.tar.gz`

Unpack the archive:

    tar xzf jazzer-*.tar.gz

Invoke the fuzzing:

    ./jazzer --cp=build/libs/hash4j-fuzz-all.jar --instrumentation_includes=com.dynatrace.** --target_class=com.dynatrace.hash4j.fuzz.Fuzz -rss_limit_mb=4096 --jvm_args=-Xss4m corpus

In this mode Jazzer will stop whenever it detects an unexpected exception 
or crashes.

You can use `--keep_going=10` to report a given number of exceptions before stopping.

See `./jazzer` for options which can control details of how Jazzer operates.
