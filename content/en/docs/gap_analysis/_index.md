---
title: Gap Analysis Example
linkTitle: Gap Analysis Example
weight: 40
---

{{% pageinfo %}}
What gaps in Ghidra's import processes need the most long term attention?
{{% /pageinfo %}}

Some features are easy or quick to add to Ghidra's import processes.  Other features
might be nice to have but just aren't worth the effort.  How do we approach features
that are probably going to be important in the long term but would require a lot of effort to address?

This section considers RISCV-64 code optimization by vector instruction insertion as an example.  Either the compiler or
the coder can choose to replace sequences of simple instructions with sequences of vector instructions.  Those vector
sequences often do not have a clean C representation in Ghidra's decompiler view, making it difficult for Ghidra users to
understand what the code is doing and to look for malware or other pathologies.

The overview introduced an approach to this sort of challenge:

1. What is a current example of this feature, especially examples that support analysis or pathologies of those features.
    * ⇒see [Examples]({{< relref "examples" >}}) 
2. How and when might this feature impact a significant number of Ghidra analysts?
    * ⇒see [Impact]({{< relref "impact" >}}) 
3. How much effort might it take Ghidra developers to fill the implied feature gap?  Do we fill it by extending the core of Ghidra, by
   generating new plugin scripts or tools, or by educating Ghidra users on how to recognize semantic patterns from raw instructions?
    * ⇒see [Effort]({{< relref "effort" >}}) 
4. Is this feature specific to RISCV systems or more broadly applicable to other processor families?  Would support for that
   feature be common to many processor families or vary widely by processor?
    * ⇒see [Scope]({{< relref "scope" >}}) 
5. What are the existing frameworks within Ghidra that might most credibly be extended to support that feature?
    * ⇒see [Existing Frameworks]({{< relref "existing_frameworks" >}}) 

