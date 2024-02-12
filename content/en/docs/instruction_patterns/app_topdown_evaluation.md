---
title: Application Top Down Analysis
linkTitle: Application Analysis
weight: 30
---

{{% pageinfo %}}
How much complexity do vector instructions add to a top down analysis?
{{% /pageinfo %}}

We know that whisper.cpp contains lots of vector instructions.  Now we want to understand how few vector instruction blocks we really need to understand.

For this analysis we will assume a specific goal - inspect the final text output phase to see if an adversary has modified the generated text.

First we want to understand the unmodified behavior using a simple demo case.  One of the whisper.cpp examples works well. It was built for the x86-64-v3 platform, not the riscv-64 gcv platform,
but that's fine - we just want to understand the rough sequencing and get a handle on the strings we might find in or near the top level main routine.


## what is the expected behavior?

>Note: added comments are flagged with a trailing `//`

```console
/opt/whisper_cpp$ ./main -f samples/jfk.wav
whisper_init_from_file_with_params_no_state: loading model from 'models/ggml-base.en.bin'
whisper_model_load: loading model
whisper_model_load: n_vocab       = 51864
whisper_model_load: n_audio_ctx   = 1500
whisper_model_load: n_audio_state = 512
whisper_model_load: n_audio_head  = 8
whisper_model_load: n_audio_layer = 6
whisper_model_load: n_text_ctx    = 448
whisper_model_load: n_text_state  = 512
whisper_model_load: n_text_head   = 8
whisper_model_load: n_text_layer  = 6
whisper_model_load: n_mels        = 80
whisper_model_load: ftype         = 1
whisper_model_load: qntvr         = 0
whisper_model_load: type          = 2 (base)
whisper_model_load: adding 1607 extra tokens
whisper_model_load: n_langs       = 99
whisper_model_load:      CPU total size =   147.46 MB (1 buffers)
whisper_model_load: model size    =  147.37 MB
whisper_init_state: kv self size  =   16.52 MB
whisper_init_state: kv cross size =   18.43 MB
whisper_init_state: compute buffer (conv)   =   14.86 MB
whisper_init_state: compute buffer (encode) =   85.99 MB
whisper_init_state: compute buffer (cross)  =    4.78 MB
whisper_init_state: compute buffer (decode) =   96.48 MB

system_info: n_threads = 4 / 16 | AVX = 1 | AVX2 = 1 | AVX512 = 0 | FMA = 1 | NEON = 0 | ARM_FMA = 0 | METAL = 0 | F16C = 1 | FP16_VA = 0 | WASM_SIMD = 0 | BLAS = 0 | SSE3 = 1 | SSSE3 = 1 | VSX = 0 | CUDA = 0 | COREML = 0 | OPENVINO = 0 | 

// done with initialization, lets run speach-to-text
main: processing 'samples/jfk.wav' (176000 samples, 11.0 sec), 4 threads, 1 processors, 5 beams + best of 5, lang = en, task = transcribe, timestamps = 1 ...

// this is the reference line our adversary wants to modify:
[00:00:00.000 --> 00:00:11.000]   And so my fellow Americans, ask not what your country can do for you, ask what you can do for your country.

// display statistics
whisper_print_timings:     load time =   183.72 ms
whisper_print_timings:     fallbacks =   0 p /   0 h
whisper_print_timings:      mel time =    10.30 ms
whisper_print_timings:   sample time =    33.90 ms /   131 runs (    0.26 ms per run)
whisper_print_timings:   encode time =   718.87 ms /     1 runs (  718.87 ms per run)
whisper_print_timings:   decode time =     8.35 ms /     2 runs (    4.17 ms per run)
whisper_print_timings:   batchd time =   150.96 ms /   125 runs (    1.21 ms per run)
whisper_print_timings:   prompt time =     0.00 ms /     1 runs (    0.00 ms per run)
whisper_print_timings:    total time =  1110.87 ms
```

The adversary wants to change the text output from "... ask what you can do for your country." to "... ask what you can do for your enemy."
They likely drop a string substitution into the code between the output of `main: processing` and `whisper_print_timings:`, probably very close to
code printing timestamp intervals like `[00:00:00.000 --> 00:00:11.000]`.

## what function names and strings look relevant?

Our RISCV-64 binary retains some function names and lots of relevant strings.  We want to accumulate strings that occur in the demo printout,
then glance at the functions that reference those strings.

For this example we will use a binary that includes some debugging type information.  Ghidra can determine names of structure types but not necessarily
the size or field names of those structures.

### strings

* `%s: processing '%s' (%d samples, %.1f sec), %d threads, %d processors, %d beams + best of %d, lang = %s, task = %s, %stimestamps = %d ...` is referenced
  near the middle of `main`
* `[%s --> %s]` is referenced by `whisper_print_segment_callback`
* `[%s --> %s]  %s\n` is referenced by `whisper_full_with_state`
* `segment` occurs in several places, suggesting that the word refers to a segment of text generated from speach between two timestamps.
* `ctx` occurs 33 times, suggesting that a context structure is used - and occasionally displayed with field names
* `error: failed to initialize whisper context\n` is referenced within `main`.  It may help in understanding internal data organization.

### functions

* `main` - Ghidra decompiles this as ~1000 C statements, including many vector statements
* `whisper_print_timings` - referenced directly in main near the end
* `whisper_full_with_state` - referenced indirectly from main via `whisper_full_parallel` and `whisper_full`
* `output_txt` - referenced directly in main, invokes I/O routines like `std::__ostream_insert<>`.  There are
  other output routines like `output_json`.  The specific output routine can be selected as a command line parameter
  to `main`.

### types and structs

Ghidra knows that these exist as names, but the details are left to us to unravel.  

* `gpt_params` and `gpt_vocab` - these look promising, at a lower ML level
* `whisper_context` - this likely holds most of the top-level data
* `whisper_full_params` and `whisper_params` - likely structures related to the optional parameters
  revealed with the `--help` command line option.
* `whisper_segment` - possibly a segment of digitized audio to be converted as speach.
* `whisper_vocab` - possible holding the text words known to the training data.

### notes

Now we have enough context to narrow the search.  We want to know:

* how does `main` call either `whisper_print_segment_callback` or `whisper_full_with_state`.
    * `whisper_full` is called directly by `main`.  Ghidra reports this to be about 3000 lines of C.  The Ghidra
      call tree suggests that this function does most of the text-to-speech tensor math and other ML heavy lifting.
    * `whisper_print_segment_callback` appears to be inserted into a C++ object vtable as a function pointer.  The object itself
      appears to be built on `main`'s stack, so we don't immediately know its size or use.  `whisper_print_segment_callback` is less than a tenth the size of
      `whisper_full_with_state`.
* how does the JFK output text get appended to the string `[%s --> %s]`?
* from what structures is the output text retrieved?
* where are those structures initialized?  How large are they, and are any of their fields named
  in diagnostic output?
* are their any diagnostic routines displaying the contents of such structures?

## next steps

A simple but tedious technique involves a mix of top-down and bottom-up analysis.  We work upwards from strings and function references, and down
from the `main` routine towards the functions associated with our target text string.  Trial and error with lots of backtracking are common here, so
switching back and forth between top-down and bottom-up exploration can provide fresh insights.

Remember that we don't want to understand any more of `whisper.cpp` than we have to.  The adversary we are chasing only wants to understand where
the generated text comes within reach.  Neither they nor we need to understand all of the ways the C++ standard library might use vector instructions
during I/O subsystem initialization.

On the other hand, they and we may need to recognize basic I/O and string handling operations, since the target text is likely to exist as either a
standard string or a standard vector of strings.

>Note: This isn't a tutorial on how to approach a C++ reverse engineering challenge - it's an
>      evaluation of how vectorization might make that more difficult and an exploration of
>      what additional tools Ghidra or Ghidra users may find useful when faced with vectorization.
>      That means we'll skip most of the non-vector analysis.

## vectorization obscures initialization

This sequence from `main` affects initialization and obscures a possible exploit vector.

```c
  vsetivli_e8m8tama(0x17);         // memcpy(puStack_110, "models/ggml-base.en.bin", 0x17)
  auVar27 = vle8_v(0xa6650);
  vsetivli_e8m8tama(0xf);          // memcpy(puStack_f0, "" [SPEAKER_TURN]", 0xf)
  auVar26 = vle8_v(0xa6668);
  puStack_f0 = auStack_e0;
  vsetivli_e8m8tama(0x17);
  vse8_v(auVar27,puStack_110);
  vsetivli_e8m8tama(0xf);
  vse8_v(auVar26,puStack_f0);
  puStack_d0 = &uStack_c0;
  vsetivli_e64m1tama(2);          // memset(lStack_b0, 0, 16)
  vmv_v_i(auVar25,0);
  vse64_v(auVar25,&lStack_b0);
  *(char *)((long)puStack_110 + 0x17) = '\0';
  ```

  If the hypothetical adversary wanted to replace the training model `ggml-base.en.bin` with a less benign model, changing the
  memory reference within `vle8_v(0xa6650)` would be a good place to do it.  Note that the compiler has interleaved instructions
  generated from the two memcpy expansions, at the cost of two extra `vsetivli` instructions.  This allows more time for the
  vector load instructions to complete.