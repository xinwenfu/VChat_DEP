# VChat: Introduction to Data Execution Prevention
> [!NOTE]
> - The following exploit and its procedures are based on an original [Blog](https://fluidattacks.com/blog/understanding-dep/) from fluid attacks.
> - Disable Windows *Real-time protection* at *Virus & threat protection* -> *Virus & threat protection settings*.
> - Don't copy the *$* sign when copying and pasting a command in this tutorial.
> - Offsets may vary depending on what version of VChat was compiled, the version of the compiler used, and any compiler flags applied during the compilation process.
___

There are a number of protections that systems put in place to prevent or limit the effectiveness of buffer overflows. 
* There are those that attempt to prevent the attacker from gaining control over the flow of execution, like [Stack Canaries](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf), which aim to protect the return address.
* There are also those such as [Address Space Layout Randomization](https://www.ibm.com/docs/en/zos/3.1.0?topic=overview-address-space-layout-randomization) that make it more difficult for overflows to be successful or locate the addresses of the target functions, and libraries they require.
* With this document, we will be focusing on something known as [Data Execution Prevention (DEP)](https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10#data-execution-prevention), with this protection scheme we set something known as the No eXecute (NX) bit on specific memory pages. This is generally a hardware-based protection (Software-based DEP does exist), and if the NX-bit of a memory page is set, the CPU will not allow the execution of instructions located within that memory page as it should be *read/write-only* (?). Looking at previous exploits, we have heavily relied on being able to execute instructions that we have placed into the stack.

#### Exploit Protections Settings

1. Open Windows Settings.

   <img src="Images/I9a.png" width=600>

2. Search for the Exploit Protection configuration menu.

   <img src="Images/I9b.png" width=600>

3. Enable DEP by default.

   <img src="Images/I9c.png" width=600>


### Exploiting With DEP

> [!IMPORTANT]
> DEP protections may not work on Virtual Machines running on specific platforms (Virtualbox Version 7.0). This may require us to run the program on some other system to show this behavior.

We will use the same [exploit1.py](./SourceCode/exploit1.py) that we compiled for the [No-Dep Exploitation section](#no-dep-exploitation), for details on the commands used to generate this please refer to the earlier section.

1. Attach VChat to the Immunity debugger and run the exploit against our VChat server while observing the results.

	https://github.com/DaintyJet/VChat-DEP/assets/60448620/fd17763a-d89c-4295-8076-327e3abce018

   1. Click on the black button highlighted below, and enter the address we decided in the previous step.

      <img src="Images/I16.png" width=600>

   2. Set a breakpoint at the desired address (Right-click).

      <img src="Images/I17.png" width=600>

   3. Run the [exploit1.py](./SourceCode/exploit1.py) program till an overflow occurs (See EIP/ESP and stack changes), you should be able to tell by the black text at the bottom the screen that says `Breakpoint at ...`.

      <img src="Images/I18.png" width=600>

   4. Step into the JMP instruction and observe the results. Notice that our instructions, in this case only the `mov` instruction is reached before an execption is raised. This is because we have DEP protections enabled and this disallows executable commands in certain memory regions such as the stack.

      <img src="Images/I12.png" width=600>

DEP is only one manner of defending against buffer overflows, when it is enabled it only makes preforming an overflow harder. It does not make them impossible, you can enable additional protections such as ASLR and Stack Canaries to make exploitations even harder. However, when DEP is the only protection enabled, we can, with relative ease, use a technique known as [Return Oriented Programming](https://dl.acm.org/doi/10.1145/2133375.2133377) to overcome the DEP protections.

## Test code
1. [exploit1.py](SourceCode/exploit1.py): Exploit the [TRUN](https://github.com/DaintyJet/VChat_TRUN) command placing a `mov`, `add`, and `sub` instruction onto the stack.

## References
[[1] Mitigate threats by using Windows 10 security features](https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10#data-execution-prevention)

[[2] No-Execute (NX) Nonpaged Pool](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/no-execute-nonpaged-pool)

[[3] Understanding binary protections (and how to bypass) with a dumb example](https://mdanilor.github.io/posts/memory-protections/)

[[4] What is NX/XD feature?](https://access.redhat.com/solutions/2936741)

[[5] StackGuard: Automatic Adaptive Detection  and Prevention of Buffer-Overflow Attacks](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)

[[6] Stack Canaries – Gingerly Sidestepping the Cage](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/)

[[7] GCC Security](https://gist.github.com/jrelo/f5c976fdc602688a0fd40288fde6d886)

[[8] Physical Address Extension](https://learn.microsoft.com/en-us/windows/win32/memory/physical-address-extension)
